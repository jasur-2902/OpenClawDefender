//! Matching rules that connect MCP events to OS events.

use clawdefender_core::event::mcp::{McpEvent, McpEventKind};
use clawdefender_core::event::os::{OsEvent, OsEventKind};

use crate::proctree::ProcessTree;

/// Which rule produced the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchRule {
    /// MCP tools/call for shell tools matched an eslogger exec event.
    ToolCallToExec,
    /// MCP resources/read with file URI matched an eslogger open event.
    ResourceReadToOpen,
    /// MCP tools/call for file tools matched a file operation.
    FileToolToFileOp,
    /// MCP tools/call for network tools matched a connect event.
    NetworkToolToConnect,
}

/// Result of a successful match between an MCP event and an OS event.
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub rule: MatchRule,
    pub time_delta: chrono::Duration,
    /// 1.0 = exact match, 0.8 = prefix match, 0.6 = substring match.
    pub confidence: f64,
}

/// Shell tool names that correspond to process execution.
const SHELL_TOOLS: &[&str] = &[
    "run_command",
    "execute",
    "bash",
    "shell",
    "terminal",
    "subprocess",
    "system",
];

/// File tool names that correspond to file operations.
const FILE_TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "create_file",
    "edit_file",
    "delete_file",
];

/// Network tool names that correspond to network operations.
const NETWORK_TOOLS: &[&str] = &[
    "fetch",
    "http_request",
    "curl",
    "wget",
    "download",
    "upload",
];

/// Try to match an MCP event to an OS event.
///
/// Returns `Some(MatchResult)` if a rule matched, `None` otherwise.
/// `server_pid` is the PID of the MCP server process whose descendants
/// we expect to produce the OS events.
pub fn try_match(
    mcp: &McpEvent,
    os: &OsEvent,
    process_tree: &ProcessTree,
    server_pid: u32,
) -> Option<MatchResult> {
    // OS event must come from a descendant of the server process
    if !is_descendant(os.pid, server_pid, process_tree) {
        return None;
    }

    let time_delta = os.timestamp - mcp.timestamp;

    match &mcp.kind {
        McpEventKind::ToolCall(tc) => {
            let tool_lower = tc.tool_name.to_lowercase();

            // Rule 1: Shell tool -> Exec
            if SHELL_TOOLS.iter().any(|t| tool_lower.contains(t)) {
                if let OsEventKind::Exec {
                    target_path, args, ..
                } = &os.kind
                {
                    let args_str = format!("{} {}", serde_json::to_string(&tc.arguments).unwrap_or_default(), tc.arguments);
                    let binary_name = target_path.rsplit('/').next().unwrap_or(target_path);

                    if args_str.contains(target_path) {
                        return Some(MatchResult {
                            rule: MatchRule::ToolCallToExec,
                            time_delta,
                            confidence: 1.0,
                        });
                    }
                    if args_str.contains(binary_name) {
                        return Some(MatchResult {
                            rule: MatchRule::ToolCallToExec,
                            time_delta,
                            confidence: 0.8,
                        });
                    }
                    // Check if any argument word matches
                    for arg in args {
                        if args_str.contains(arg.as_str()) && !arg.is_empty() {
                            return Some(MatchResult {
                                rule: MatchRule::ToolCallToExec,
                                time_delta,
                                confidence: 0.6,
                            });
                        }
                    }
                }
            }

            // Rule 3: File tool -> File op
            if FILE_TOOLS.iter().any(|t| tool_lower.contains(t)) {
                let mcp_paths = extract_paths_from_args(&tc.arguments);
                match &os.kind {
                    OsEventKind::Open { path, .. }
                    | OsEventKind::Close { path }
                    | OsEventKind::Unlink { path }
                    | OsEventKind::SetMode { path, .. } => {
                        if let Some(confidence) = path_match_confidence(path, &mcp_paths) {
                            return Some(MatchResult {
                                rule: MatchRule::FileToolToFileOp,
                                time_delta,
                                confidence,
                            });
                        }
                    }
                    OsEventKind::Rename { source, dest } => {
                        let c1 = path_match_confidence(source, &mcp_paths);
                        let c2 = path_match_confidence(dest, &mcp_paths);
                        let best = c1.into_iter().chain(c2).reduce(f64::max);
                        if let Some(confidence) = best {
                            return Some(MatchResult {
                                rule: MatchRule::FileToolToFileOp,
                                time_delta,
                                confidence,
                            });
                        }
                    }
                    _ => {}
                }
            }

            // Rule 4: Network tool -> Connect
            if NETWORK_TOOLS.iter().any(|t| tool_lower.contains(t)) {
                if let OsEventKind::Connect { address, .. } = &os.kind {
                    let args_str = tc.arguments.to_string();
                    // Exact IP match in arguments
                    if args_str.contains(address.as_str()) {
                        return Some(MatchResult {
                            rule: MatchRule::NetworkToolToConnect,
                            time_delta,
                            confidence: 1.0,
                        });
                    }
                    // Fuzzy match: if the args contain a URL/hostname and
                    // the OS event connects to an external IP, it's likely related.
                    // Extract hostnames from URLs in args and check if any non-loopback
                    // connect happened.
                    if !address.starts_with("127.")
                        && address != "::1"
                        && address != "0.0.0.0"
                        && args_contains_url_or_hostname(&args_str)
                    {
                        return Some(MatchResult {
                            rule: MatchRule::NetworkToolToConnect,
                            time_delta,
                            confidence: 0.6,
                        });
                    }
                }
            }

            None
        }
        McpEventKind::ResourceRead(rr) => {
            // Rule 2: Resource read -> File open
            if let Some(file_path) = rr.uri.strip_prefix("file://") {
                if let OsEventKind::Open { path, .. } = &os.kind {
                    let canonical_mcp = canonicalize_path(file_path);
                    let canonical_os = canonicalize_path(path);

                    if canonical_os == canonical_mcp {
                        return Some(MatchResult {
                            rule: MatchRule::ResourceReadToOpen,
                            time_delta,
                            confidence: 1.0,
                        });
                    }
                    if canonical_os.starts_with(&canonical_mcp) {
                        return Some(MatchResult {
                            rule: MatchRule::ResourceReadToOpen,
                            time_delta,
                            confidence: 0.8,
                        });
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Check if an argument string contains a URL or hostname pattern.
fn args_contains_url_or_hostname(args: &str) -> bool {
    let lower = args.to_lowercase();
    // Check for URL schemes
    if lower.contains("http://") || lower.contains("https://") || lower.contains("ftp://") {
        return true;
    }
    // Check for common hostname-like patterns (word.word with known TLDs)
    // This is a simple heuristic, not exhaustive
    for word in lower.split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-') {
        if word.contains('.') && word.len() > 3 {
            let parts: Vec<&str> = word.split('.').collect();
            if parts.len() >= 2 && parts.last().is_some_and(|tld| tld.len() >= 2) {
                return true;
            }
        }
    }
    false
}

/// Check if `pid` is a descendant of `ancestor_pid` by walking the process tree.
fn is_descendant(pid: u32, ancestor_pid: u32, tree: &ProcessTree) -> bool {
    if pid == ancestor_pid {
        return true;
    }
    let ancestry = tree.get_ancestry(pid);
    ancestry.iter().any(|p| p.pid == ancestor_pid)
}

/// Canonicalize a path: expand `~` to home dir, normalize separators.
pub fn canonicalize_path(path: &str) -> String {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            format!("{}/{}", home, rest)
        } else {
            path.to_string()
        }
    } else if path == "~" {
        home_dir().unwrap_or_else(|| path.to_string())
    } else {
        path.to_string()
    };

    // Normalize: remove trailing slash, collapse double slashes
    let mut result = expanded.replace("//", "/");
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }
    result
}

/// Get the home directory path as a string.
fn home_dir() -> Option<String> {
    std::env::var("HOME").ok()
}

/// Extract file paths from MCP tool arguments JSON.
pub fn extract_paths_from_args(args: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_paths(args, &mut paths);
    paths
}

fn collect_paths(value: &serde_json::Value, paths: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            // Heuristic: strings that look like file paths
            if s.starts_with('/')
                || s.starts_with("~/")
                || s.starts_with("./")
                || s.starts_with("../")
                || s.contains(".txt")
                || s.contains(".rs")
                || s.contains(".py")
                || s.contains(".js")
                || s.contains(".json")
                || s.contains(".toml")
                || s.contains(".yaml")
                || s.contains(".yml")
                || s.contains(".md")
                || s.contains(".sh")
            {
                paths.push(s.clone());
            }
        }
        serde_json::Value::Object(map) => {
            // Check keys that commonly hold paths
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                if key_lower == "path"
                    || key_lower == "file"
                    || key_lower == "filename"
                    || key_lower == "file_path"
                    || key_lower == "filepath"
                    || key_lower == "source"
                    || key_lower == "dest"
                    || key_lower == "destination"
                    || key_lower == "target"
                {
                    if let serde_json::Value::String(s) = val {
                        paths.push(s.clone());
                    }
                }
                collect_paths(val, paths);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_paths(item, paths);
            }
        }
        _ => {}
    }
}

/// Compare an OS path against a list of MCP-extracted paths.
/// Returns the highest confidence if any match, or None.
fn path_match_confidence(os_path: &str, mcp_paths: &[String]) -> Option<f64> {
    let canonical_os = canonicalize_path(os_path);
    let mut best: Option<f64> = None;

    for mcp_path in mcp_paths {
        let canonical_mcp = canonicalize_path(mcp_path);

        if canonical_os == canonical_mcp {
            return Some(1.0); // exact match, can't do better
        }
        if canonical_os.starts_with(&canonical_mcp) || canonical_mcp.starts_with(&canonical_os) {
            best = Some(best.map_or(0.8, |b: f64| b.max(0.8)));
        }
        // Check filename-only match
        let os_name = canonical_os.rsplit('/').next().unwrap_or(&canonical_os);
        let mcp_name = canonical_mcp.rsplit('/').next().unwrap_or(&canonical_mcp);
        if os_name == mcp_name && !os_name.is_empty() {
            best = Some(best.map_or(0.6, |b: f64| b.max(0.6)));
        }
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_tilde() {
        std::env::set_var("HOME", "/Users/dev");
        assert_eq!(canonicalize_path("~/file.txt"), "/Users/dev/file.txt");
        assert_eq!(
            canonicalize_path("~/Projects/app/"),
            "/Users/dev/Projects/app"
        );
    }

    #[test]
    fn test_canonicalize_absolute() {
        assert_eq!(canonicalize_path("/tmp/foo.txt"), "/tmp/foo.txt");
    }

    #[test]
    fn test_extract_paths_from_args() {
        let args = serde_json::json!({
            "path": "~/test.txt",
            "content": "hello world"
        });
        let paths = extract_paths_from_args(&args);
        assert!(paths.contains(&"~/test.txt".to_string()));
    }

    #[test]
    fn test_path_match_exact() {
        let mcp_paths = vec!["/tmp/foo.txt".to_string()];
        assert_eq!(path_match_confidence("/tmp/foo.txt", &mcp_paths), Some(1.0));
    }

    #[test]
    fn test_path_match_prefix() {
        let mcp_paths = vec!["/tmp/project".to_string()];
        assert_eq!(
            path_match_confidence("/tmp/project/src/main.rs", &mcp_paths),
            Some(0.8)
        );
    }

    #[test]
    fn test_is_descendant_direct() {
        let mut tree = ProcessTree::new();
        tree.insert(crate::proctree::ProcessInfo {
            pid: 100,
            ppid: 0,
            name: "server".into(),
            path: "/usr/bin/server".into(),
            args: vec![],
            start_time: None,
        });
        tree.insert(crate::proctree::ProcessInfo {
            pid: 200,
            ppid: 100,
            name: "child".into(),
            path: "/bin/ls".into(),
            args: vec![],
            start_time: None,
        });
        assert!(is_descendant(200, 100, &tree));
        assert!(!is_descendant(200, 999, &tree));
    }
}
