//! Security sandbox for tool execution.
//!
//! Every tool call passes through the sandbox which enforces:
//! - Path allowlists (no reading arbitrary files)
//! - Command allowlists (no running arbitrary shell commands)
//! - Rate limiting (max calls per session)
//! - Audit logging (every execution is recorded)

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::tools::{ToolCall, ToolExecution, ToolResult};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("Access denied: path '{0}' is not in the allowed set")]
    PathNotAllowed(String),

    #[error("Access denied: command '{0}' is not in the allowed set")]
    CommandNotAllowed(String),

    #[error("Tool call limit exceeded ({0}/{1})")]
    RateLimitExceeded(u32, u32),

    #[error("File too large: {0} bytes (max {1})")]
    FileTooLarge(usize, usize),

    #[error("Command timed out after {0}s")]
    CommandTimeout(u64),

    #[error("Unknown tool: {0}")]
    UnknownTool(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Pending actions (for action tools that require user approval)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: String,
    pub action_type: String,
    pub description: String,
    pub proposed_by: String,
    pub created_at: String,
    pub status: ActionStatus,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionStatus {
    Pending,
    Approved,
    Rejected,
}

// ---------------------------------------------------------------------------
// Sandbox configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub allowed_read_paths: Vec<String>,
    pub allowed_commands: Vec<String>,
    pub max_file_read_size: usize,
    pub max_command_timeout: Duration,
    pub max_tool_calls_per_session: u32,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allowed_read_paths: default_allowed_paths(),
            allowed_commands: default_allowed_commands(),
            max_file_read_size: 100 * 1024, // 100 KB
            max_command_timeout: Duration::from_secs(10),
            max_tool_calls_per_session: 50,
        }
    }
}

fn default_allowed_paths() -> Vec<String> {
    vec![
        "~/Library/Application Support/Claude/claude_desktop_config.json".into(),
        "~/.config/clawdefender/*".into(),
        "~/.ssh/config".into(),
        "~/.zshrc".into(),
        "~/.bashrc".into(),
        "~/.bash_profile".into(),
        "/etc/hosts".into(),
        "/etc/ssh/sshd_config".into(),
    ]
}

fn default_allowed_commands() -> Vec<String> {
    vec![
        "csrutil status".into(),
        "spctl --status".into(),
        "fdesetup status".into(),
        "pfctl -s info".into(),
        "launchctl list | grep -i clawdefender".into(),
        "ps aux | grep -i mcp".into(),
        "networksetup -listallnetworkservices".into(),
    ]
}

// ---------------------------------------------------------------------------
// ToolSandbox
// ---------------------------------------------------------------------------

pub struct ToolSandbox {
    allowed_read_paths: Vec<String>,
    allowed_commands: Vec<String>,
    max_file_read_size: usize,
    max_command_timeout: Duration,
    max_tool_calls_per_session: u32,
    tool_call_count: AtomicU32,
    audit_log: Mutex<Vec<ToolExecution>>,
    pending_actions: Mutex<Vec<PendingAction>>,
}

impl ToolSandbox {
    /// Create a sandbox with default settings.
    pub fn new() -> Self {
        Self::with_config(SandboxConfig::default())
    }

    /// Create a sandbox from explicit configuration.
    pub fn with_config(config: SandboxConfig) -> Self {
        Self {
            allowed_read_paths: config.allowed_read_paths,
            allowed_commands: config.allowed_commands,
            max_file_read_size: config.max_file_read_size,
            max_command_timeout: config.max_command_timeout,
            max_tool_calls_per_session: config.max_tool_calls_per_session,
            tool_call_count: AtomicU32::new(0),
            audit_log: Mutex::new(Vec::new()),
            pending_actions: Mutex::new(Vec::new()),
        }
    }

    // -- Validation ---------------------------------------------------------

    /// Resolve `~` to the user's home directory.
    fn expand_tilde(path: &str) -> String {
        if path.starts_with("~/") || path == "~" {
            if let Some(home) = dirs_home() {
                return path.replacen('~', &home, 1);
            }
        }
        path.to_string()
    }

    /// Check whether `path` is in the read allowlist.
    ///
    /// Supports exact matches and simple glob patterns (trailing `/*`).
    pub fn validate_path(&self, path: &str) -> bool {
        let expanded = Self::expand_tilde(path);
        let canonical = std::path::Path::new(&expanded);

        for pattern in &self.allowed_read_paths {
            let expanded_pattern = Self::expand_tilde(pattern);

            if expanded_pattern.ends_with("/*") {
                // Directory prefix glob — allow anything under that directory.
                let prefix = &expanded_pattern[..expanded_pattern.len() - 2];
                let prefix_path = std::path::Path::new(prefix);
                if canonical.starts_with(prefix_path) {
                    return true;
                }
            } else {
                // Exact match.
                let pattern_path = std::path::Path::new(&expanded_pattern);
                if canonical == pattern_path {
                    return true;
                }
            }
        }
        false
    }

    /// Check whether `command` is in the command allowlist (exact match).
    pub fn validate_command(&self, command: &str) -> bool {
        self.allowed_commands.iter().any(|c| c == command)
    }

    /// Increment call counter and check rate limit.
    pub fn check_rate_limit(&self) -> Result<(), ToolError> {
        let prev = self.tool_call_count.fetch_add(1, Ordering::SeqCst);
        if prev >= self.max_tool_calls_per_session {
            // Roll back so we don't keep inflating the counter.
            self.tool_call_count.fetch_sub(1, Ordering::SeqCst);
            return Err(ToolError::RateLimitExceeded(
                prev,
                self.max_tool_calls_per_session,
            ));
        }
        Ok(())
    }

    /// Current tool call count.
    pub fn call_count(&self) -> u32 {
        self.tool_call_count.load(Ordering::SeqCst)
    }

    /// Return a snapshot of the audit log.
    pub fn audit_log(&self) -> Vec<ToolExecution> {
        self.audit_log.lock().unwrap().clone()
    }

    /// Return pending actions awaiting user approval.
    pub fn pending_actions(&self) -> Vec<PendingAction> {
        self.pending_actions.lock().unwrap().clone()
    }

    // -- Execution ----------------------------------------------------------

    /// Main dispatcher: validate, execute, audit-log, return result.
    pub async fn execute_tool(&self, call: &ToolCall, session_id: &str) -> ToolResult {
        let start = Instant::now();
        self.check_rate_limit().unwrap_or_else(|e| {
            // We still want to return a ToolResult, so we handle this below.
            tracing::warn!("{e}");
        });

        // Check rate limit before dispatching.
        if self.tool_call_count.load(Ordering::SeqCst) > self.max_tool_calls_per_session {
            return ToolResult {
                tool_use_id: call.id.clone(),
                content: format!(
                    "Error: tool call limit exceeded ({}/{})",
                    self.tool_call_count.load(Ordering::SeqCst),
                    self.max_tool_calls_per_session,
                ),
                is_error: true,
            };
        }

        let result = match call.name.as_str() {
            // Investigation tools
            "query_events" => self.handle_query_events(&call.input),
            "get_server_profile" => self.handle_get_server_profile(&call.input),
            "get_event_detail" => self.handle_get_event_detail(&call.input),
            "check_reputation" => self.handle_check_reputation(&call.input),
            "get_policy" => self.handle_get_policy(&call.input),
            "get_system_posture" => self.handle_get_system_posture(&call.input),
            "search_events" => self.handle_search_events(&call.input),
            // System inspection tools
            "read_file" => self.handle_read_file(&call.input).await,
            "list_directory" => self.handle_list_directory(&call.input).await,
            "run_command" => self.handle_run_command(&call.input).await,
            // Action tools
            "suggest_policy_change" => self.handle_suggest_policy_change(&call.input),
            "create_alert" => self.handle_create_alert(&call.input),
            "suggest_remediation" => self.handle_suggest_remediation(&call.input),
            unknown => Err(ToolError::UnknownTool(unknown.to_string())),
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        let (content, is_error) = match result {
            Ok(c) => (c, false),
            Err(e) => (format!("Error: {e}"), true),
        };

        // Compute output hash (privacy: we never store the full output).
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let output_hash = hex::encode(hasher.finalize());

        // Summarise input for audit (first 120 chars of the JSON).
        let input_json = serde_json::to_string(&call.input).unwrap_or_default();
        let input_summary = if input_json.len() > 120 {
            format!("{}...", &input_json[..120])
        } else {
            input_json
        };

        let execution = ToolExecution {
            tool_name: call.name.clone(),
            input_summary,
            output_hash,
            timestamp: Utc::now().to_rfc3339(),
            session_id: session_id.to_string(),
            success: !is_error,
            duration_ms,
        };

        if let Ok(mut log) = self.audit_log.lock() {
            log.push(execution);
        }

        ToolResult {
            tool_use_id: call.id.clone(),
            content,
            is_error,
        }
    }

    // -- Investigation tool handlers (placeholder data) ---------------------

    fn handle_query_events(&self, input: &Value) -> Result<String, ToolError> {
        let time_range = input
            .get("time_range")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("time_range is required".into()))?;

        let server = input.get("server").and_then(|v| v.as_str());
        let severity = input.get("severity").and_then(|v| v.as_str());
        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(50);

        let mock = json!({
            "time_range": time_range,
            "server_filter": server,
            "severity_filter": severity,
            "limit": limit,
            "total_count": 0,
            "events": []
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    fn handle_get_server_profile(&self, input: &Value) -> Result<String, ToolError> {
        let server_name = input
            .get("server_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("server_name is required".into()))?;

        let mock = json!({
            "server_name": server_name,
            "trust_level": "unknown",
            "tool_usage": [],
            "file_access_patterns": [],
            "network_patterns": [],
            "anomaly_history": [],
            "first_seen": null,
            "last_seen": null
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    fn handle_get_event_detail(&self, input: &Value) -> Result<String, ToolError> {
        let event_id = input
            .get("event_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("event_id is required".into()))?;

        let mock = json!({
            "event_id": event_id,
            "found": false,
            "detail": null
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    fn handle_check_reputation(&self, input: &Value) -> Result<String, ToolError> {
        let target = input
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("target is required".into()))?;

        let mock = json!({
            "target": target,
            "in_blocklist": false,
            "ioc_matches": [],
            "reputation_score": null,
            "notes": "No data available (placeholder)"
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    fn handle_get_policy(&self, _input: &Value) -> Result<String, ToolError> {
        let mock = json!({
            "rules": [],
            "version": "0.0.0",
            "last_updated": null
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    fn handle_get_system_posture(&self, _input: &Value) -> Result<String, ToolError> {
        let mock = json!({
            "sip_enabled": null,
            "firewall_enabled": null,
            "filevault_enabled": null,
            "gatekeeper_enabled": null,
            "note": "Placeholder — run system inspection commands for live data"
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    fn handle_search_events(&self, input: &Value) -> Result<String, ToolError> {
        let query = input
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("query is required".into()))?;

        let limit = input
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(20)
            .min(50);

        let mock = json!({
            "query": query,
            "limit": limit,
            "total_matches": 0,
            "results": []
        });
        Ok(serde_json::to_string_pretty(&mock).unwrap())
    }

    // -- System inspection tool handlers ------------------------------------

    async fn handle_read_file(&self, input: &Value) -> Result<String, ToolError> {
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("path is required".into()))?;

        if !self.validate_path(path) {
            return Err(ToolError::PathNotAllowed(path.to_string()));
        }

        let expanded = Self::expand_tilde(path);
        let metadata = tokio::fs::metadata(&expanded).await?;
        let size = metadata.len() as usize;
        if size > self.max_file_read_size {
            return Err(ToolError::FileTooLarge(size, self.max_file_read_size));
        }

        let contents = tokio::fs::read_to_string(&expanded).await?;
        Ok(contents)
    }

    async fn handle_list_directory(&self, input: &Value) -> Result<String, ToolError> {
        let path = input
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("path is required".into()))?;

        if !self.validate_path(path) {
            return Err(ToolError::PathNotAllowed(path.to_string()));
        }

        let expanded = Self::expand_tilde(path);
        let mut entries = Vec::new();
        let mut dir = tokio::fs::read_dir(&expanded).await?;
        while let Some(entry) = dir.next_entry().await? {
            let meta = entry.metadata().await.ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            entries.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "size": size,
                "is_dir": is_dir,
            }));
        }

        Ok(serde_json::to_string_pretty(&json!({
            "path": path,
            "entries": entries
        }))
        .unwrap())
    }

    async fn handle_run_command(&self, input: &Value) -> Result<String, ToolError> {
        let command = input
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("command is required".into()))?;

        if !self.validate_command(command) {
            return Err(ToolError::CommandNotAllowed(command.to_string()));
        }

        let timeout = self.max_command_timeout;
        let cmd = command.to_string();

        let output = tokio::time::timeout(timeout, async {
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .output()
                .await
        })
        .await
        .map_err(|_| ToolError::CommandTimeout(timeout.as_secs()))?
        .map_err(ToolError::Io)?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let result = json!({
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
        });

        Ok(serde_json::to_string_pretty(&result).unwrap())
    }

    // -- Action tool handlers -----------------------------------------------

    fn handle_suggest_policy_change(&self, input: &Value) -> Result<String, ToolError> {
        let rule_type = input
            .get("rule_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("rule_type is required".into()))?;
        let target = input
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("target is required".into()))?;
        let action = input
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("action is required".into()))?;
        let rationale = input
            .get("rationale")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("rationale is required".into()))?;

        let pending = PendingAction {
            id: Uuid::new_v4().to_string(),
            action_type: "policy_change".into(),
            description: format!("{action} {rule_type} for '{target}': {rationale}"),
            proposed_by: "claude".into(),
            created_at: Utc::now().to_rfc3339(),
            status: ActionStatus::Pending,
            details: input.clone(),
        };

        let id = pending.id.clone();
        if let Ok(mut actions) = self.pending_actions.lock() {
            actions.push(pending);
        }

        Ok(format!(
            "Action proposed (id: {id}). Awaiting user approval."
        ))
    }

    fn handle_create_alert(&self, input: &Value) -> Result<String, ToolError> {
        let severity = input
            .get("severity")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("severity is required".into()))?;
        let title = input
            .get("title")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("title is required".into()))?;
        let description = input
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("description is required".into()))?;

        let pending = PendingAction {
            id: Uuid::new_v4().to_string(),
            action_type: "alert".into(),
            description: format!("[{severity}] {title}: {description}"),
            proposed_by: "claude".into(),
            created_at: Utc::now().to_rfc3339(),
            status: ActionStatus::Pending,
            details: input.clone(),
        };

        let id = pending.id.clone();
        if let Ok(mut actions) = self.pending_actions.lock() {
            actions.push(pending);
        }

        Ok(format!(
            "Alert created (id: {id}). Awaiting user approval."
        ))
    }

    fn handle_suggest_remediation(&self, input: &Value) -> Result<String, ToolError> {
        let issue = input
            .get("issue")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("issue is required".into()))?;
        let recommendation = input
            .get("recommendation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("recommendation is required".into()))?;

        let pending = PendingAction {
            id: Uuid::new_v4().to_string(),
            action_type: "remediation".into(),
            description: format!("Issue: {issue} — Recommendation: {recommendation}"),
            proposed_by: "claude".into(),
            created_at: Utc::now().to_rfc3339(),
            status: ActionStatus::Pending,
            details: input.clone(),
        };

        let id = pending.id.clone();
        if let Ok(mut actions) = self.pending_actions.lock() {
            actions.push(pending);
        }

        Ok(format!(
            "Remediation proposed (id: {id}). Awaiting user approval."
        ))
    }
}

impl Default for ToolSandbox {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the user's home directory as a `String`.
fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sandbox() -> ToolSandbox {
        ToolSandbox::new()
    }

    // -- Path validation ----------------------------------------------------

    #[test]
    fn test_path_validation_allows_ssh_config() {
        let s = sandbox();
        assert!(s.validate_path("~/.ssh/config"));
    }

    #[test]
    fn test_path_validation_blocks_ssh_key() {
        let s = sandbox();
        assert!(!s.validate_path("~/.ssh/id_rsa"));
    }

    #[test]
    fn test_path_validation_blocks_arbitrary() {
        let s = sandbox();
        assert!(!s.validate_path("/etc/passwd"));
    }

    #[test]
    fn test_path_validation_allows_clawdefender_config() {
        let s = sandbox();
        assert!(s.validate_path("~/.config/clawdefender/settings.toml"));
    }

    #[test]
    fn test_path_validation_allows_etc_hosts() {
        let s = sandbox();
        assert!(s.validate_path("/etc/hosts"));
    }

    // -- Command validation -------------------------------------------------

    #[test]
    fn test_command_validation_allows_csrutil() {
        let s = sandbox();
        assert!(s.validate_command("csrutil status"));
    }

    #[test]
    fn test_command_validation_blocks_rm() {
        let s = sandbox();
        assert!(!s.validate_command("rm -rf /"));
    }

    #[test]
    fn test_command_validation_blocks_curl() {
        let s = sandbox();
        assert!(!s.validate_command("curl http://evil.com"));
    }

    #[test]
    fn test_command_validation_allows_fdesetup() {
        let s = sandbox();
        assert!(s.validate_command("fdesetup status"));
    }

    // -- Rate limiting ------------------------------------------------------

    #[test]
    fn test_rate_limit_enforcement() {
        let s = ToolSandbox::with_config(SandboxConfig {
            max_tool_calls_per_session: 3,
            ..Default::default()
        });

        assert!(s.check_rate_limit().is_ok()); // 1
        assert!(s.check_rate_limit().is_ok()); // 2
        assert!(s.check_rate_limit().is_ok()); // 3
        assert!(s.check_rate_limit().is_err()); // 4 — over limit
    }

    // -- Unknown tool -------------------------------------------------------

    #[tokio::test]
    async fn test_unknown_tool_returns_error() {
        let s = sandbox();
        let call = ToolCall {
            id: "test-1".into(),
            name: "totally_fake_tool".into(),
            input: json!({}),
        };
        let result = s.execute_tool(&call, "test-session").await;
        assert!(result.is_error);
        assert!(result.content.contains("Unknown tool"));
    }

    // -- read_file blocked --------------------------------------------------

    #[tokio::test]
    async fn test_read_file_blocks_unauthorized() {
        let s = sandbox();
        let call = ToolCall {
            id: "test-2".into(),
            name: "read_file".into(),
            input: json!({ "path": "/etc/shadow" }),
        };
        let result = s.execute_tool(&call, "test-session").await;
        assert!(result.is_error);
        assert!(result.content.contains("Access denied"));
    }

    // -- run_command blocked ------------------------------------------------

    #[tokio::test]
    async fn test_run_command_blocks_unauthorized() {
        let s = sandbox();
        let call = ToolCall {
            id: "test-3".into(),
            name: "run_command".into(),
            input: json!({ "command": "whoami" }),
        };
        let result = s.execute_tool(&call, "test-session").await;
        assert!(result.is_error);
        assert!(result.content.contains("Access denied"));
    }

    // -- Audit log ----------------------------------------------------------

    #[tokio::test]
    async fn test_audit_log_records_executions() {
        let s = sandbox();
        let call = ToolCall {
            id: "test-4".into(),
            name: "get_policy".into(),
            input: json!({}),
        };
        s.execute_tool(&call, "session-abc").await;
        let log = s.audit_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].tool_name, "get_policy");
        assert_eq!(log[0].session_id, "session-abc");
        assert!(log[0].success);
    }

    // -- Action tools create pending actions --------------------------------

    #[tokio::test]
    async fn test_suggest_policy_change_creates_pending_action() {
        let s = sandbox();
        let call = ToolCall {
            id: "test-5".into(),
            name: "suggest_policy_change".into(),
            input: json!({
                "rule_type": "block_server",
                "target": "evil-mcp",
                "action": "add",
                "rationale": "Detected suspicious behavior"
            }),
        };
        let result = s.execute_tool(&call, "session-xyz").await;
        assert!(!result.is_error);
        assert!(result.content.contains("Awaiting user approval"));

        let actions = s.pending_actions();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_type, "policy_change");
        assert_eq!(actions[0].status, ActionStatus::Pending);
    }
}
