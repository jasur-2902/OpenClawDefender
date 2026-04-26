//! Scan-specific tools available only during scan and investigation sessions.
//!
//! These tools provide deeper system inspection capabilities that go beyond
//! the base tool set. They are gated by [`SessionType`] — scan sessions get
//! the full set, investigation sessions get a subset, and chat/report sessions
//! get none.

use regex::Regex;
use serde_json::{json, Value};
use std::time::Duration;

use crate::agent_session::SessionType;
use crate::tools::ToolDefinition;

// ---------------------------------------------------------------------------
// Tool availability by session type
// ---------------------------------------------------------------------------

/// Returns the complete tool set available for a given session type.
///
/// - **Scan**: base tools + all scan tools
/// - **Investigate**: base tools + analysis-only scan tools
/// - **Chat / Report**: base tools only
pub fn get_available_tools(session_type: &SessionType) -> Vec<ToolDefinition> {
    let mut tools = crate::tools::get_all_tool_definitions();

    match session_type {
        SessionType::Scan { .. } => {
            tools.extend(get_scan_tool_definitions());
        }
        SessionType::Investigate { .. } => {
            tools.extend(get_investigation_tool_definitions());
        }
        SessionType::Chat | SessionType::Report { .. } => {
            // Base tools only
        }
    }

    tools
}

// ---------------------------------------------------------------------------
// Scan-only tool definitions
// ---------------------------------------------------------------------------

/// All six scan-specific tool definitions.
pub fn get_scan_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // ── Deeper file inspection ────────────────────────────────────
        ToolDefinition {
            name: "read_file_extended".into(),
            description: "Read files from an expanded scan allowlist including MCP client \
                configs, environment files, LaunchAgents, Docker config, and Kubernetes \
                config. Private key contents are automatically redacted."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path (or ~-prefixed) to the file to read"
                    }
                },
                "required": ["path"]
            }),
        },
        // ── Deeper system inspection ──────────────────────────────────
        ToolDefinition {
            name: "run_scan_command".into(),
            description: "Execute commands from an expanded scan allowlist: launchctl list, \
                dscl user listing, LaunchAgent inspection, stat, mdls, xattr, plutil, \
                csrutil status, spctl, fdesetup, firewall status, networksetup, \
                scutil --dns, ls -la, softwareupdate, system_profiler. \
                Destructive, network, and write commands are denied."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The command to execute (must match the scan allowlist)"
                    }
                },
                "required": ["command"]
            }),
        },
        // ── Analysis tools ────────────────────────────────────────────
        ToolDefinition {
            name: "compare_with_baseline".into(),
            description: "Compare the current behavioral profile of an MCP server against \
                its initial baseline. Returns a list of changes, timestamps, and risk delta."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server to compare"
                    }
                },
                "required": ["server_name"]
            }),
        },
        ToolDefinition {
            name: "get_event_timeline".into(),
            description: "Get a chronological timeline of security events for an MCP server \
                within a given time window."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server"
                    },
                    "hours": {
                        "type": "number",
                        "description": "Number of hours to look back",
                        "default": 24
                    }
                },
                "required": ["server_name"]
            }),
        },
        ToolDefinition {
            name: "check_file_permissions".into(),
            description: "Check file ownership, group, permissions, and ACLs. Also reports \
                whether the file is readable by any MCP server process."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file to inspect"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "get_network_destinations".into(),
            description: "List unique network destinations contacted by an MCP server, \
                including host, port, first/last seen timestamps, and connection counts."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Name of the MCP server"
                    }
                },
                "required": ["server_name"]
            }),
        },
    ]
}

/// Subset of scan tools available during investigation sessions.
///
/// Investigation gets the analysis tools but NOT the deeper file/command
/// inspection tools (`read_file_extended`, `run_scan_command`).
fn get_investigation_tool_definitions() -> Vec<ToolDefinition> {
    get_scan_tool_definitions()
        .into_iter()
        .filter(|t| {
            matches!(
                t.name.as_str(),
                "compare_with_baseline"
                    | "get_event_timeline"
                    | "check_file_permissions"
                    | "get_network_destinations"
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scan tool executor
// ---------------------------------------------------------------------------

/// Executes scan-specific tools with their own path and command allowlists.
pub struct ScanToolExecutor {
    scan_path_allowlist: Vec<String>,
    scan_command_allowlist: Vec<String>,
    max_file_read_size: usize,
    max_command_timeout: Duration,
}

impl ScanToolExecutor {
    pub fn new() -> Self {
        Self {
            scan_path_allowlist: vec![
                "~/.env".into(),
                "~/.npmrc".into(),
                "~/.pypirc".into(),
                "~/Library/LaunchAgents/*".into(),
                "~/.docker/config.json".into(),
                "~/.kube/config".into(),
                // MCP configs are already in the base allowlist
                // SSH directory (for permission checking, key contents are redacted)
                "~/.ssh/*".into(),
            ],
            scan_command_allowlist: vec![
                "launchctl list".into(),
                "dscl . -list /Users".into(),
                "ls -la ~/Library/LaunchAgents/".into(),
                "stat".into(),
                "mdls".into(),
                "xattr -l".into(),
                "plutil -p".into(),
                // System security status (all read-only)
                "csrutil status".into(),
                "spctl --status".into(),
                "fdesetup status".into(),
                "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate".into(),
                "softwareupdate --list".into(),
                "system_profiler SPFirewallDataType".into(),
                // File listing for credential investigation (metadata only)
                "ls -la ~/.ssh/".into(),
                "ls -la ~/.aws/".into(),
                "ls -la ~/.gnupg/".into(),
                // Network investigation
                "networksetup -listallnetworkservices".into(),
                "scutil --dns".into(),
                // General ls -la as prefix for any path
                "ls -la".into(),
            ],
            max_file_read_size: 100 * 1024, // 100 KB
            max_command_timeout: Duration::from_secs(10),
        }
    }

    /// Main dispatcher for scan-specific tool calls.
    pub async fn execute_scan_tool(
        &self,
        tool_name: &str,
        input: &Value,
    ) -> Result<String, String> {
        match tool_name {
            "read_file_extended" => self.read_file_extended(input).await,
            "run_scan_command" => self.run_scan_command(input).await,
            "compare_with_baseline" => self.compare_with_baseline(input),
            "get_event_timeline" => self.get_event_timeline(input),
            "check_file_permissions" => self.check_file_permissions(input).await,
            "get_network_destinations" => self.get_network_destinations(input),
            _ => Err(format!("Unknown scan tool: {}", tool_name)),
        }
    }

    /// Check whether a scan tool name is handled by this executor.
    pub fn handles_tool(&self, tool_name: &str) -> bool {
        matches!(
            tool_name,
            "read_file_extended"
                | "run_scan_command"
                | "compare_with_baseline"
                | "get_event_timeline"
                | "check_file_permissions"
                | "get_network_destinations"
        )
    }

    /// Return a reference to the scan path allowlist.
    pub fn path_allowlist(&self) -> &[String] {
        &self.scan_path_allowlist
    }

    /// Return a reference to the scan command allowlist.
    pub fn command_allowlist(&self) -> &[String] {
        &self.scan_command_allowlist
    }

    // -- Tool implementations -----------------------------------------------

    async fn read_file_extended(&self, input: &Value) -> Result<String, String> {
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "path is required".to_string())?;

        if !self.validate_scan_path(path) {
            return Err(format!(
                "Access denied: path '{}' is not in the scan allowlist",
                path
            ));
        }

        let expanded = expand_tilde(path);

        let metadata = tokio::fs::metadata(&expanded)
            .await
            .map_err(|e| format!("Cannot access file: {}", e))?;

        let size = metadata.len() as usize;
        if size > self.max_file_read_size {
            return Err(format!(
                "File too large: {} bytes (max {})",
                size, self.max_file_read_size
            ));
        }

        let contents = tokio::fs::read_to_string(&expanded)
            .await
            .map_err(|e| format!("Cannot read file: {}", e))?;

        // Defense-in-depth: redact private keys before returning
        let redacted = redact_private_keys(&contents);

        Ok(redacted)
    }

    async fn run_scan_command(&self, input: &Value) -> Result<String, String> {
        let command = input
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "command is required".to_string())?;

        if !self.validate_scan_command(command) {
            return Err(format!(
                "Access denied: command '{}' is not in the scan allowlist",
                command
            ));
        }

        // Expand tilde in the command for execution
        let expanded_cmd = expand_tilde(command);

        let timeout = self.max_command_timeout;
        let output = tokio::time::timeout(timeout, async {
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&expanded_cmd)
                .output()
                .await
        })
        .await
        .map_err(|_| format!("Command timed out after {}s", timeout.as_secs()))?
        .map_err(|e| format!("Command execution failed: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let result = json!({
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn compare_with_baseline(&self, input: &Value) -> Result<String, String> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_name is required".to_string())?;

        // Placeholder — real implementation would query the behavioral profile store
        let result = json!({
            "server_name": server_name,
            "changes": [],
            "first_seen": null,
            "last_profiled": null,
            "risk_delta": 0.0,
            "note": "No baseline data available yet — the server has not been profiled"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn get_event_timeline(&self, input: &Value) -> Result<String, String> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_name is required".to_string())?;

        let hours = input.get("hours").and_then(|v| v.as_f64()).unwrap_or(24.0);

        // Placeholder — real implementation would query the event store
        let result = json!({
            "server_name": server_name,
            "hours": hours,
            "timeline": [],
            "note": "No events recorded for this server in the specified window"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    async fn check_file_permissions(&self, input: &Value) -> Result<String, String> {
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "path is required".to_string())?;

        let expanded = expand_tilde(path);

        let metadata = tokio::fs::metadata(&expanded)
            .await
            .map_err(|e| format!("Cannot access file: {}", e))?;

        // Extract Unix permissions
        #[cfg(unix)]
        let (owner, group, permissions) = {
            use std::os::unix::fs::MetadataExt;
            let mode = metadata.mode();
            let perm_str = format!("{:o}", mode & 0o7777);
            let uid = metadata.uid();
            let gid = metadata.gid();
            (uid.to_string(), gid.to_string(), perm_str)
        };

        #[cfg(not(unix))]
        let (owner, group, permissions) = {
            (
                "unknown".to_string(),
                "unknown".to_string(),
                "unknown".to_string(),
            )
        };

        let result = json!({
            "path": path,
            "owner": owner,
            "group": group,
            "permissions": permissions,
            "acls": [],
            "readable_by_mcp": null,
            "size": metadata.len(),
            "is_dir": metadata.is_dir(),
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    fn get_network_destinations(&self, input: &Value) -> Result<String, String> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "server_name is required".to_string())?;

        // Placeholder — real implementation would query the network monitor
        let result = json!({
            "server_name": server_name,
            "destinations": [],
            "note": "No network activity recorded for this server"
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    // -- Validation ---------------------------------------------------------

    /// Check whether `path` is in the scan path allowlist.
    fn validate_scan_path(&self, path: &str) -> bool {
        let expanded = expand_tilde(path);
        let canonical = std::path::Path::new(&expanded);

        for pattern in &self.scan_path_allowlist {
            let expanded_pattern = expand_tilde(pattern);

            if expanded_pattern.ends_with("/*") {
                let prefix = &expanded_pattern[..expanded_pattern.len() - 2];
                let prefix_path = std::path::Path::new(prefix);
                if canonical.starts_with(prefix_path) {
                    return true;
                }
            } else {
                let pattern_path = std::path::Path::new(&expanded_pattern);
                if canonical == pattern_path {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether `command` is in the scan command allowlist.
    ///
    /// Supports exact matches and prefix matches for commands that take
    /// arguments (e.g. `stat`, `mdls`, `xattr -l`, `plutil -p`).
    fn validate_scan_command(&self, command: &str) -> bool {
        let trimmed = command.trim();

        for allowed in &self.scan_command_allowlist {
            // Exact match
            if trimmed == allowed {
                return true;
            }
            // Prefix match for commands that take a file argument
            // (e.g. "stat /some/file" matches allowlist entry "stat")
            if matches!(
                allowed.as_str(),
                "stat" | "mdls" | "xattr -l" | "plutil -p" | "ls -la"
            ) && trimmed.starts_with(allowed.as_str())
                && trimmed[allowed.len()..].starts_with(' ')
            {
                // Deny path traversal and dangerous patterns in the argument
                let arg = trimmed[allowed.len()..].trim();
                if !arg.contains("..")
                    && !arg.contains(';')
                    && !arg.contains('|')
                    && !arg.contains('`')
                    && !arg.contains('$')
                {
                    return true;
                }
            }
        }
        false
    }
}

impl Default for ScanToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tool result enrichment
// ---------------------------------------------------------------------------

/// Add contextual metadata to tool results before sending to the LLM.
pub fn enrich_tool_result(tool_name: &str, _input: &Value, raw_result: &str) -> String {
    match tool_name {
        "read_file_extended" => {
            format!(
                "{}\n\n[Scan tool: file contents above may have been redacted for security]",
                raw_result
            )
        }
        "get_server_profile" => {
            format!(
                "{}\n\n[Note: compare_with_baseline can show changes over time]",
                raw_result
            )
        }
        "compare_with_baseline" => {
            format!(
                "{}\n\n[Note: use get_event_timeline for chronological detail]",
                raw_result
            )
        }
        _ => raw_result.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Private key redaction
// ---------------------------------------------------------------------------

/// Strip private key blocks from file content (defense-in-depth).
///
/// Replaces `-----BEGIN ... PRIVATE KEY-----` through `-----END ... PRIVATE KEY-----`
/// with a `[REDACTED: private key]` placeholder.
pub fn redact_private_keys(content: &str) -> String {
    let re =
        Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
            .expect("private key regex must compile");

    re.replace_all(content, "[REDACTED: private key]")
        .to_string()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") || path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen('~', &home, 1);
        }
    }
    path.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Tool definitions ---------------------------------------------------

    #[test]
    fn test_scan_tool_definitions_count() {
        let defs = get_scan_tool_definitions();
        assert_eq!(defs.len(), 6, "expected 6 scan tool definitions");
    }

    #[test]
    fn test_scan_tool_definitions_have_valid_schema() {
        let defs = get_scan_tool_definitions();
        for def in &defs {
            assert!(!def.name.is_empty(), "tool name must not be empty");
            assert!(
                !def.description.is_empty(),
                "tool '{}' must have a description",
                def.name
            );
            assert!(
                def.input_schema.is_object(),
                "tool '{}' schema must be an object",
                def.name
            );
            let schema = def.input_schema.as_object().unwrap();
            assert_eq!(
                schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "tool '{}' schema type must be 'object'",
                def.name
            );
            assert!(
                schema.contains_key("properties"),
                "tool '{}' schema must have 'properties'",
                def.name
            );
            assert!(
                schema.contains_key("required"),
                "tool '{}' schema must have 'required'",
                def.name
            );
        }
    }

    // -- Tool availability by session type ----------------------------------

    #[test]
    fn test_scan_session_includes_scan_tools() {
        let tools = get_available_tools(&SessionType::Scan {
            playbook: "full".into(),
        });
        let base_count = crate::tools::get_all_tool_definitions().len();
        let scan_count = get_scan_tool_definitions().len();
        assert_eq!(tools.len(), base_count + scan_count);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"read_file_extended"));
        assert!(names.contains(&"run_scan_command"));
        assert!(names.contains(&"compare_with_baseline"));
        assert!(names.contains(&"get_event_timeline"));
        assert!(names.contains(&"check_file_permissions"));
        assert!(names.contains(&"get_network_destinations"));
    }

    #[test]
    fn test_chat_session_excludes_scan_tools() {
        let tools = get_available_tools(&SessionType::Chat);
        let base_count = crate::tools::get_all_tool_definitions().len();
        assert_eq!(tools.len(), base_count);

        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"read_file_extended"));
        assert!(!names.contains(&"run_scan_command"));
        assert!(!names.contains(&"compare_with_baseline"));
    }

    #[test]
    fn test_report_session_excludes_scan_tools() {
        let tools = get_available_tools(&SessionType::Report {
            report_type: "weekly".into(),
        });
        let base_count = crate::tools::get_all_tool_definitions().len();
        assert_eq!(tools.len(), base_count);
    }

    #[test]
    fn test_investigate_session_includes_subset() {
        let tools = get_available_tools(&SessionType::Investigate {
            event_id: "evt-1".into(),
        });
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

        // Investigation gets analysis tools
        assert!(names.contains(&"compare_with_baseline"));
        assert!(names.contains(&"get_event_timeline"));
        assert!(names.contains(&"check_file_permissions"));
        assert!(names.contains(&"get_network_destinations"));

        // But NOT the deeper inspection tools
        assert!(!names.contains(&"read_file_extended"));
        assert!(!names.contains(&"run_scan_command"));
    }

    // -- Path allowlist validation ------------------------------------------

    #[test]
    fn test_scan_path_allows_env_file() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.env"));
    }

    #[test]
    fn test_scan_path_allows_npmrc() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.npmrc"));
    }

    #[test]
    fn test_scan_path_allows_pypirc() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.pypirc"));
    }

    #[test]
    fn test_scan_path_allows_docker_config() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.docker/config.json"));
    }

    #[test]
    fn test_scan_path_allows_kube_config() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.kube/config"));
    }

    #[test]
    fn test_scan_path_allows_launch_agents() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/Library/LaunchAgents/com.example.plist"));
    }

    #[test]
    fn test_scan_path_blocks_arbitrary_files() {
        let executor = ScanToolExecutor::new();
        assert!(!executor.validate_scan_path("/etc/passwd"));
        assert!(!executor.validate_scan_path("/etc/shadow"));
        assert!(!executor.validate_scan_path("~/Documents/secrets.txt"));
    }

    #[test]
    fn test_scan_path_allows_ssh_keys_with_redaction() {
        // SSH files are now in the scan allowlist — private key contents
        // are automatically redacted by redact_private_keys()
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.ssh/id_rsa"));
        assert!(executor.validate_scan_path("~/.ssh/id_ed25519"));
    }

    // -- Command allowlist validation ---------------------------------------

    #[test]
    fn test_scan_command_allows_launchctl() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("launchctl list"));
    }

    #[test]
    fn test_scan_command_allows_dscl() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("dscl . -list /Users"));
    }

    #[test]
    fn test_scan_command_allows_stat_with_arg() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("stat /some/file"));
    }

    #[test]
    fn test_scan_command_allows_mdls_with_arg() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("mdls /some/file.plist"));
    }

    #[test]
    fn test_scan_command_allows_xattr_with_arg() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("xattr -l /some/file"));
    }

    #[test]
    fn test_scan_command_allows_plutil_with_arg() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("plutil -p /some/file.plist"));
    }

    #[test]
    fn test_scan_command_blocks_destructive() {
        let executor = ScanToolExecutor::new();
        assert!(!executor.validate_scan_command("rm -rf /"));
        assert!(!executor.validate_scan_command("chmod 777 /etc/passwd"));
    }

    #[test]
    fn test_scan_command_blocks_network() {
        let executor = ScanToolExecutor::new();
        assert!(!executor.validate_scan_command("curl http://evil.com"));
        assert!(!executor.validate_scan_command("wget http://evil.com"));
    }

    #[test]
    fn test_scan_command_blocks_path_traversal() {
        let executor = ScanToolExecutor::new();
        assert!(!executor.validate_scan_command("stat ../../etc/passwd"));
    }

    #[test]
    fn test_scan_command_blocks_command_injection() {
        let executor = ScanToolExecutor::new();
        assert!(!executor.validate_scan_command("stat /tmp/foo; rm -rf /"));
        assert!(!executor.validate_scan_command("stat /tmp/foo | cat /etc/passwd"));
        assert!(!executor.validate_scan_command("stat `whoami`"));
        assert!(!executor.validate_scan_command("stat $HOME/.ssh/id_rsa"));
    }

    #[test]
    fn test_scan_command_allows_csrutil() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("csrutil status"));
    }

    #[test]
    fn test_scan_command_allows_spctl() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("spctl --status"));
    }

    #[test]
    fn test_scan_command_allows_fdesetup() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("fdesetup status"));
    }

    #[test]
    fn test_scan_command_allows_firewall_check() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command(
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"
        ));
    }

    #[test]
    fn test_scan_command_allows_networksetup() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("networksetup -listallnetworkservices"));
    }

    #[test]
    fn test_scan_command_allows_scutil_dns() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("scutil --dns"));
    }

    #[test]
    fn test_scan_command_allows_ls_la_with_path() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_command("ls -la /some/path"));
        assert!(executor.validate_scan_command("ls -la ~/.ssh/"));
    }

    #[test]
    fn test_scan_path_allows_ssh_files() {
        let executor = ScanToolExecutor::new();
        assert!(executor.validate_scan_path("~/.ssh/id_rsa"));
        assert!(executor.validate_scan_path("~/.ssh/authorized_keys"));
        assert!(executor.validate_scan_path("~/.ssh/config"));
    }

    // -- Private key redaction ----------------------------------------------

    #[test]
    fn test_redact_rsa_private_key() {
        let content = "some config\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\nmore config";
        let redacted = redact_private_keys(content);
        assert!(redacted.contains("[REDACTED: private key]"));
        assert!(!redacted.contains("MIIE"));
        assert!(redacted.contains("some config"));
        assert!(redacted.contains("more config"));
    }

    #[test]
    fn test_redact_ec_private_key() {
        let content = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----";
        let redacted = redact_private_keys(content);
        assert_eq!(redacted, "[REDACTED: private key]");
    }

    #[test]
    fn test_redact_generic_private_key() {
        let content = "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----";
        let redacted = redact_private_keys(content);
        assert_eq!(redacted, "[REDACTED: private key]");
    }

    #[test]
    fn test_no_redaction_without_keys() {
        let content = "just some normal config file\nno keys here";
        let redacted = redact_private_keys(content);
        assert_eq!(redacted, content);
    }

    #[test]
    fn test_redact_multiple_keys() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nkey1\n-----END RSA PRIVATE KEY-----\n\
            middle text\n\
            -----BEGIN EC PRIVATE KEY-----\nkey2\n-----END EC PRIVATE KEY-----";
        let redacted = redact_private_keys(content);
        assert_eq!(
            redacted.matches("[REDACTED: private key]").count(),
            2,
            "both keys should be redacted"
        );
        assert!(redacted.contains("middle text"));
    }

    // -- Tool result enrichment ---------------------------------------------

    #[test]
    fn test_enrich_read_file_extended() {
        let result = enrich_tool_result("read_file_extended", &json!({}), "file contents");
        assert!(result.contains("file contents"));
        assert!(result.contains("redacted for security"));
    }

    #[test]
    fn test_enrich_get_server_profile() {
        let result = enrich_tool_result("get_server_profile", &json!({}), "profile data");
        assert!(result.contains("profile data"));
        assert!(result.contains("compare_with_baseline"));
    }

    #[test]
    fn test_enrich_compare_with_baseline() {
        let result = enrich_tool_result("compare_with_baseline", &json!({}), "baseline data");
        assert!(result.contains("baseline data"));
        assert!(result.contains("get_event_timeline"));
    }

    #[test]
    fn test_enrich_passthrough() {
        let result = enrich_tool_result("run_scan_command", &json!({}), "output");
        assert_eq!(result, "output");
    }

    // -- ScanToolExecutor handles_tool --------------------------------------

    #[test]
    fn test_handles_tool_known() {
        let executor = ScanToolExecutor::new();
        assert!(executor.handles_tool("read_file_extended"));
        assert!(executor.handles_tool("run_scan_command"));
        assert!(executor.handles_tool("compare_with_baseline"));
        assert!(executor.handles_tool("get_event_timeline"));
        assert!(executor.handles_tool("check_file_permissions"));
        assert!(executor.handles_tool("get_network_destinations"));
    }

    #[test]
    fn test_handles_tool_unknown() {
        let executor = ScanToolExecutor::new();
        assert!(!executor.handles_tool("read_file"));
        assert!(!executor.handles_tool("run_command"));
        assert!(!executor.handles_tool("totally_fake"));
    }

    // -- Executor dispatching -----------------------------------------------

    #[tokio::test]
    async fn test_executor_unknown_tool_error() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool("not_a_real_tool", &json!({}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown scan tool"));
    }

    #[tokio::test]
    async fn test_executor_read_file_extended_denied() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool("read_file_extended", &json!({ "path": "/etc/shadow" }))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Access denied"));
    }

    #[tokio::test]
    async fn test_executor_run_scan_command_denied() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool("run_scan_command", &json!({ "command": "rm -rf /" }))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Access denied"));
    }

    #[tokio::test]
    async fn test_executor_compare_with_baseline() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool(
                "compare_with_baseline",
                &json!({ "server_name": "test-server" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("test-server"));
        assert!(output.contains("changes"));
    }

    #[tokio::test]
    async fn test_executor_get_event_timeline() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool(
                "get_event_timeline",
                &json!({ "server_name": "test-server", "hours": 12 }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("test-server"));
        assert!(output.contains("timeline"));
    }

    #[tokio::test]
    async fn test_executor_get_network_destinations() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool(
                "get_network_destinations",
                &json!({ "server_name": "test-server" }),
            )
            .await;
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("test-server"));
        assert!(output.contains("destinations"));
    }

    #[tokio::test]
    async fn test_executor_missing_required_field() {
        let executor = ScanToolExecutor::new();
        let result = executor
            .execute_scan_tool("compare_with_baseline", &json!({}))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("server_name is required"));
    }

    // -- expand_tilde -------------------------------------------------------

    #[test]
    fn test_expand_tilde_with_home() {
        // This test relies on HOME being set, which it normally is in CI and dev.
        if std::env::var("HOME").is_ok() {
            let expanded = expand_tilde("~/test");
            assert!(!expanded.starts_with('~'));
            assert!(expanded.ends_with("/test"));
        }
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let result = expand_tilde("/absolute/path");
        assert_eq!(result, "/absolute/path");
    }
}
