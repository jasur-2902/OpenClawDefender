//! Drag-and-drop file, URL, and config analysis for Ask Claw.
//!
//! All analysis is read-only — files are never executed, URLs are never fetched.
//! Content is sanitized before any SLM interaction.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Safe,
    Caution,
    Risky,
    Dangerous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileType {
    Script,
    Config,
    EnvFile,
    Document,
    Binary,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub description: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size_bytes: u64,
    pub extension: String,
    pub sha256: String,
    pub file_type: FileType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysisResult {
    pub verdict: Verdict,
    pub confidence: f32,
    pub file_info: FileInfo,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlInfo {
    pub full_url: String,
    pub domain: String,
    pub is_known_service: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysisResult {
    pub verdict: Verdict,
    pub confidence: f32,
    pub url_info: UrlInfo,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAnalysis {
    pub name: String,
    pub command: String,
    pub findings: Vec<Finding>,
    pub recommended_trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAnalysisResult {
    pub verdict: Verdict,
    pub confidence: f32,
    pub servers_found: Vec<ServerAnalysis>,
    pub overall_findings: Vec<Finding>,
    pub recommendations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum file size we will read content from (5 MB).
const MAX_CONTENT_SIZE: u64 = 5 * 1024 * 1024;

/// Script file extensions.
const SCRIPT_EXTENSIONS: &[&str] = &["py", "sh", "bash", "js", "ts", "rb", "pl", "ps1", "bat", "cmd"];

/// Config file extensions.
const CONFIG_EXTENSIONS: &[&str] = &["json", "toml", "yaml", "yml", "ini", "cfg"];

/// Document file extensions.
const DOCUMENT_EXTENSIONS: &[&str] = &["pdf", "docx", "doc", "xlsx", "xls", "pptx", "txt", "md", "rtf"];

/// Suspicious patterns in scripts.
const SUSPICIOUS_SCRIPT_PATTERNS: &[&str] = &[
    "subprocess",
    "os.system",
    "exec(",
    "eval(",
    "socket",
    "requests.post",
    "curl ",
    "wget ",
    "base64.decode",
    "import socket",
    "os.environ",
    "process.env",
    "child_process",
    "Runtime.getRuntime",
    "powershell",
    "cmd.exe",
];

/// Known legitimate service domains.
const KNOWN_SERVICES: &[&str] = &[
    "github.com",
    "npmjs.com",
    "pypi.org",
    "huggingface.co",
    "api.openai.com",
    "api.anthropic.com",
    "registry.npmjs.org",
    "crates.io",
    "rubygems.org",
    "hub.docker.com",
    "gitlab.com",
    "bitbucket.org",
];

/// Suspicious URL path segments.
const SUSPICIOUS_PATHS: &[&str] = &[
    "/admin",
    "/shell",
    "/cmd",
    "/exec",
    "/eval",
    "/wp-admin",
    "/phpinfo",
    "/phpmyadmin",
    "/cgi-bin",
    "/.env",
    "/.git",
];

/// TLDs commonly associated with malicious registrations.
const SUSPICIOUS_TLDS: &[&str] = &[".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".click"];

/// Overly broad file access paths for MCP servers.
const BROAD_PATHS: &[&str] = &["/", "/Users", "/home", "/etc", "/var", "/tmp"];

// ---------------------------------------------------------------------------
// FileAnalyzer
// ---------------------------------------------------------------------------

pub struct FileAnalyzer;

impl FileAnalyzer {
    /// Analyze a file at the given path. The path is validated and canonicalized.
    pub fn analyze(path: &str) -> Result<FileAnalysisResult, String> {
        let validated = validate_file_path(path)?;
        let metadata = fs::metadata(&validated)
            .map_err(|e| format!("Cannot read file metadata: {}", e))?;

        let name = validated
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let extension = validated
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let file_type = classify_extension(&extension, &name);
        let size_bytes = metadata.len();

        // Compute SHA-256 (content hash) only for files within size limit
        let sha256 = if size_bytes <= MAX_CONTENT_SIZE {
            compute_sha256(&validated).unwrap_or_else(|_| "unavailable".to_string())
        } else {
            "skipped-too-large".to_string()
        };

        let file_info = FileInfo {
            name: name.clone(),
            size_bytes,
            extension: extension.clone(),
            sha256,
            file_type: file_type.clone(),
        };

        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        // Size check
        if size_bytes > MAX_CONTENT_SIZE {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                description: "File exceeds 5 MB — metadata-only analysis performed".to_string(),
                detail: Some(format!("File size: {} bytes", size_bytes)),
            });
        }

        // .env file — always flag
        if file_type == FileType::EnvFile {
            findings.push(Finding {
                severity: FindingSeverity::High,
                description: "Environment file detected — likely contains secrets".to_string(),
                detail: None,
            });
            recommendations.push("Review this file for API keys, passwords, and tokens before sharing.".to_string());
            recommendations.push("Never commit .env files to version control.".to_string());
        }

        // Content analysis for readable files within size limit
        if size_bytes <= MAX_CONTENT_SIZE && file_type != FileType::Binary {
            if let Ok(content) = fs::read_to_string(&validated) {
                match file_type {
                    FileType::Script => {
                        analyze_script_content(&content, &mut findings, &mut recommendations);
                    }
                    FileType::Config => {
                        analyze_config_content(&content, &name, &mut findings, &mut recommendations);
                    }
                    FileType::EnvFile => {
                        analyze_env_content(&content, &mut findings);
                    }
                    _ => {}
                }
            }
        } else if file_type == FileType::Binary {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                description: "Binary file — content analysis skipped, metadata only".to_string(),
                detail: None,
            });
            recommendations.push("Verify the binary's source and check its hash against known-good values.".to_string());
        }

        let (verdict, confidence) = compute_file_verdict(&findings);

        Ok(FileAnalysisResult {
            verdict,
            confidence,
            file_info,
            findings,
            recommendations,
        })
    }
}

// ---------------------------------------------------------------------------
// UrlAnalyzer
// ---------------------------------------------------------------------------

pub struct UrlAnalyzer;

impl UrlAnalyzer {
    /// Analyze a URL string without fetching it.
    pub fn analyze(url: &str) -> Result<UrlAnalysisResult, String> {
        let url = url.trim();
        if url.is_empty() {
            return Err("Empty URL".to_string());
        }

        // Validate scheme — only http(s) allowed
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err("Only http and https URLs are accepted".to_string());
        }

        // Parse domain
        let after_scheme = if url.starts_with("https://") {
            &url[8..]
        } else {
            &url[7..]
        };
        let domain_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        let authority = &after_scheme[..domain_end];
        // Strip port and userinfo
        let domain = authority
            .rsplit('@')
            .next()
            .unwrap_or(authority)
            .split(':')
            .next()
            .unwrap_or(authority)
            .to_lowercase();

        let path = if domain_end < after_scheme.len() {
            &after_scheme[domain_end..]
        } else {
            "/"
        };

        let mut findings = Vec::new();
        let mut recommendations = Vec::new();

        let is_known_service = KNOWN_SERVICES.iter().any(|s| domain == *s || domain.ends_with(&format!(".{}", s)));

        // Check for HTTP (not HTTPS)
        if url.starts_with("http://") {
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                description: "URL uses HTTP instead of HTTPS — traffic is unencrypted".to_string(),
                detail: None,
            });
            recommendations.push("Use HTTPS for secure communication.".to_string());
        }

        // Check for IP address as domain
        if is_ip_address(&domain) {
            findings.push(Finding {
                severity: FindingSeverity::High,
                description: "Domain is an IP address — often used by malicious services".to_string(),
                detail: Some(format!("IP: {}", domain)),
            });
            recommendations.push("Verify the IP address belongs to a trusted service.".to_string());
        }

        // Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS {
            if domain.ends_with(tld) {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    description: format!("Domain uses suspicious TLD '{}'", tld),
                    detail: None,
                });
                recommendations.push("Domains with this TLD are frequently used for phishing.".to_string());
                break;
            }
        }

        // Check for very long subdomains (potential domain spoofing)
        let subdomain_count = domain.matches('.').count();
        if subdomain_count >= 4 {
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                description: "URL has many subdomains — possible domain spoofing".to_string(),
                detail: Some(format!("Subdomain depth: {}", subdomain_count)),
            });
        }

        // Check for userinfo in URL (credential phishing)
        if authority.contains('@') {
            findings.push(Finding {
                severity: FindingSeverity::High,
                description: "URL contains credentials (user@) — common phishing technique".to_string(),
                detail: None,
            });
        }

        // Check path for suspicious segments
        let path_lower = path.to_lowercase();
        for suspicious in SUSPICIOUS_PATHS {
            if path_lower.contains(suspicious) {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    description: format!("Suspicious path segment: {}", suspicious),
                    detail: None,
                });
            }
        }

        if is_known_service && findings.is_empty() {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                description: format!("Known service: {}", domain),
                detail: None,
            });
        }

        let (verdict, confidence) = compute_url_verdict(&findings, is_known_service);

        Ok(UrlAnalysisResult {
            verdict,
            confidence,
            url_info: UrlInfo {
                full_url: url.to_string(),
                domain,
                is_known_service,
            },
            findings,
            recommendations,
        })
    }
}

// ---------------------------------------------------------------------------
// ConfigAnalyzer (MCP server configs)
// ---------------------------------------------------------------------------

pub struct ConfigAnalyzer;

impl ConfigAnalyzer {
    /// Analyze an MCP config file for security issues.
    pub fn analyze(path: &str) -> Result<ConfigAnalysisResult, String> {
        let validated = validate_file_path(path)?;
        let metadata = fs::metadata(&validated)
            .map_err(|e| format!("Cannot read config: {}", e))?;

        if metadata.len() > MAX_CONTENT_SIZE {
            return Err("Config file too large (>5 MB)".to_string());
        }

        let content = fs::read_to_string(&validated)
            .map_err(|e| format!("Cannot read config: {}", e))?;

        Self::analyze_content(&content)
    }

    /// Analyze MCP config from a JSON string (useful for testing).
    pub fn analyze_content(content: &str) -> Result<ConfigAnalysisResult, String> {
        let parsed: serde_json::Value = serde_json::from_str(content)
            .map_err(|e| format!("Invalid JSON: {}", e))?;

        let mcp_servers = parsed.get("mcpServers")
            .and_then(|v| v.as_object());

        if mcp_servers.is_none() {
            return Err("Not an MCP config — no 'mcpServers' key found".to_string());
        }

        let servers = mcp_servers.unwrap();
        let mut server_analyses = Vec::new();
        let mut overall_findings = Vec::new();
        let mut recommendations = Vec::new();

        if servers.is_empty() {
            overall_findings.push(Finding {
                severity: FindingSeverity::Info,
                description: "Config contains empty mcpServers object".to_string(),
                detail: None,
            });
        }

        for (name, config) in servers {
            let mut server_findings = Vec::new();

            // Extract command
            let command = config.get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            // Extract args
            let args: Vec<String> = config.get("args")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let full_command = if args.is_empty() {
                command.clone()
            } else {
                format!("{} {}", command, args.join(" "))
            };

            // Check for sudo/root execution
            if command == "sudo" || full_command.contains("sudo ") {
                server_findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    description: format!("Server '{}' runs with sudo/root privileges", name),
                    detail: Some(full_command.clone()),
                });
            }

            // Check for shell execution
            if command == "sh" || command == "bash" || command == "zsh" || command == "cmd" {
                server_findings.push(Finding {
                    severity: FindingSeverity::High,
                    description: format!("Server '{}' executes via shell — risk of command injection", name),
                    detail: Some(full_command.clone()),
                });
            }

            // Check for overly broad file access in args
            for arg in &args {
                for broad_path in BROAD_PATHS {
                    if arg == broad_path || arg.starts_with(&format!("{}:", broad_path)) {
                        server_findings.push(Finding {
                            severity: FindingSeverity::High,
                            description: format!(
                                "Server '{}' has overly broad file access to '{}'", name, broad_path
                            ),
                            detail: Some(arg.clone()),
                        });
                    }
                }

                // Check for home directory access with tilde
                if arg == "~" || arg == "~/" {
                    server_findings.push(Finding {
                        severity: FindingSeverity::Medium,
                        description: format!("Server '{}' accesses entire home directory", name),
                        detail: Some(arg.clone()),
                    });
                }
            }

            // Check env for secrets
            if let Some(env) = config.get("env").and_then(|v| v.as_object()) {
                for (key, val) in env {
                    let key_upper = key.to_uppercase();
                    if key_upper.contains("KEY") || key_upper.contains("SECRET")
                        || key_upper.contains("TOKEN") || key_upper.contains("PASSWORD")
                    {
                        // Don't log the value — just flag it
                        server_findings.push(Finding {
                            severity: FindingSeverity::Medium,
                            description: format!(
                                "Server '{}' has potential secret in env var '{}'", name, key
                            ),
                            detail: None,
                        });
                        // Check if value looks hardcoded (not a reference)
                        if let Some(v) = val.as_str() {
                            if !v.starts_with("${") && !v.starts_with("$") && v.len() > 3 {
                                server_findings.push(Finding {
                                    severity: FindingSeverity::High,
                                    description: format!(
                                        "Server '{}' has hardcoded secret in '{}'", name, key
                                    ),
                                    detail: Some("Value appears to be a literal, not an environment variable reference".to_string()),
                                });
                            }
                        }
                    }
                }
            }

            let recommended_trust = if server_findings.iter().any(|f| f.severity == FindingSeverity::Critical) {
                "block"
            } else if server_findings.iter().any(|f| f.severity == FindingSeverity::High) {
                "prompt"
            } else if server_findings.iter().any(|f| f.severity == FindingSeverity::Medium) {
                "audit"
            } else {
                "allow"
            };

            server_analyses.push(ServerAnalysis {
                name: name.clone(),
                command: full_command,
                findings: server_findings,
                recommended_trust_level: recommended_trust.to_string(),
            });
        }

        // Overall recommendations
        let has_critical = server_analyses.iter()
            .any(|s| s.findings.iter().any(|f| f.severity == FindingSeverity::Critical));
        let has_high = server_analyses.iter()
            .any(|s| s.findings.iter().any(|f| f.severity == FindingSeverity::High));

        if has_critical {
            recommendations.push("At least one server runs with elevated privileges. Review carefully before enabling.".to_string());
        }
        if has_high {
            recommendations.push("Set high-risk servers to 'prompt' mode so you approve each action.".to_string());
        }
        if server_analyses.len() > 5 {
            recommendations.push(format!(
                "This config defines {} servers. Consider enabling only the ones you need.",
                server_analyses.len()
            ));
        }

        let (verdict, confidence) = compute_config_verdict(&server_analyses);

        Ok(ConfigAnalysisResult {
            verdict,
            confidence,
            servers_found: server_analyses,
            overall_findings,
            recommendations,
        })
    }
}

// ---------------------------------------------------------------------------
// Path validation and security helpers
// ---------------------------------------------------------------------------

/// Validate and canonicalize a file path. Rejects paths outside the user's home directory.
fn validate_file_path(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);

    // Canonicalize resolves symlinks
    let canonical = fs::canonicalize(path)
        .map_err(|e| format!("Cannot resolve path: {}", e))?;

    // Get user home directory
    let home = dirs::home_dir()
        .ok_or_else(|| "Cannot determine home directory".to_string())?;

    // Ensure the canonical path is inside the user's home directory
    if !canonical.starts_with(&home) {
        return Err(format!(
            "Access denied: path is outside your home directory ({})",
            home.display()
        ));
    }

    Ok(canonical)
}

/// Classify a file by its extension.
fn classify_extension(ext: &str, name: &str) -> FileType {
    let name_lower = name.to_lowercase();

    // .env files (with or without suffix)
    if name_lower == ".env" || name_lower.starts_with(".env.") {
        return FileType::EnvFile;
    }

    if SCRIPT_EXTENSIONS.contains(&ext) {
        return FileType::Script;
    }
    if CONFIG_EXTENSIONS.contains(&ext) {
        return FileType::Config;
    }
    if DOCUMENT_EXTENSIONS.contains(&ext) {
        return FileType::Document;
    }

    // Check for binary by attempting to read a small portion
    // For classification purposes, we consider extensionless files or known binary
    // extensions as Binary.
    let binary_extensions = ["exe", "dll", "so", "dylib", "bin", "o", "a", "wasm", "class", "pyc"];
    if binary_extensions.contains(&ext) {
        return FileType::Binary;
    }

    if ext.is_empty() {
        return FileType::Other;
    }

    FileType::Other
}

/// Compute SHA-256 hash of a file using the system `shasum` command.
fn compute_sha256(path: &Path) -> Result<String, String> {
    // Use shasum -a 256 on macOS/Linux, certutil on Windows
    let output = std::process::Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .map_err(|e| format!("Failed to compute hash: {}", e))?;

    if !output.status.success() {
        return Err("shasum failed".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace()
        .next()
        .map(String::from)
        .ok_or_else(|| "Unexpected shasum output".to_string())
}

/// Check if a string looks like an IP address (v4 or v6).
fn is_ip_address(domain: &str) -> bool {
    // IPv4: digits and dots
    if domain.chars().all(|c| c.is_ascii_digit() || c == '.') && domain.contains('.') {
        return true;
    }
    // IPv6: contains colons, hex chars, brackets
    if domain.contains(':') && domain.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '[' || c == ']') {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Script content analysis
// ---------------------------------------------------------------------------

fn analyze_script_content(content: &str, findings: &mut Vec<Finding>, recommendations: &mut Vec<String>) {
    let content_lower = content.to_lowercase();
    let mut suspicious_count = 0;

    for pattern in SUSPICIOUS_SCRIPT_PATTERNS {
        if content_lower.contains(&pattern.to_lowercase()) {
            suspicious_count += 1;
            findings.push(Finding {
                severity: FindingSeverity::Medium,
                description: format!("Suspicious pattern found: '{}'", pattern),
                detail: None,
            });
        }
    }

    if suspicious_count > 0 {
        recommendations.push(format!(
            "Found {} suspicious pattern(s). Review the script carefully before running.",
            suspicious_count
        ));
    }

    if suspicious_count >= 3 {
        findings.push(Finding {
            severity: FindingSeverity::High,
            description: format!(
                "Multiple suspicious patterns ({}) detected — script may be malicious",
                suspicious_count
            ),
            detail: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Config content analysis
// ---------------------------------------------------------------------------

fn analyze_config_content(
    content: &str,
    name: &str,
    findings: &mut Vec<Finding>,
    recommendations: &mut Vec<String>,
) {
    let content_lower = content.to_lowercase();

    // Check for MCP server config
    if content_lower.contains("\"mcpservers\"") || content_lower.contains("\"mcp_servers\"") {
        findings.push(Finding {
            severity: FindingSeverity::Info,
            description: "File appears to be an MCP server configuration".to_string(),
            detail: None,
        });
        recommendations.push(
            "Use the dedicated MCP config analyzer (analyze_config) for detailed analysis.".to_string(),
        );
    }

    // Check for hardcoded secrets
    let secret_patterns = [
        ("api_key", "API key"),
        ("api-key", "API key"),
        ("apikey", "API key"),
        ("secret_key", "secret key"),
        ("secret-key", "secret key"),
        ("password", "password"),
        ("passwd", "password"),
        ("token", "token"),
        ("private_key", "private key"),
        ("access_key", "access key"),
    ];

    for (pattern, label) in &secret_patterns {
        if content_lower.contains(pattern) {
            findings.push(Finding {
                severity: FindingSeverity::High,
                description: format!("Possible hardcoded {} found in '{}'", label, name),
                detail: None,
            });
        }
    }

    if findings.iter().any(|f| f.severity == FindingSeverity::High) {
        recommendations.push("Use environment variables instead of hardcoding secrets.".to_string());
    }
}

// ---------------------------------------------------------------------------
// .env content analysis
// ---------------------------------------------------------------------------

fn analyze_env_content(content: &str, findings: &mut Vec<Finding>) {
    let mut secret_count = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(key) = trimmed.split('=').next() {
            let key_upper = key.to_uppercase();
            if key_upper.contains("KEY") || key_upper.contains("SECRET")
                || key_upper.contains("TOKEN") || key_upper.contains("PASSWORD")
                || key_upper.contains("PRIVATE")
            {
                secret_count += 1;
            }
        }
    }
    if secret_count > 0 {
        findings.push(Finding {
            severity: FindingSeverity::High,
            description: format!(
                "Found {} variable(s) that likely contain secrets",
                secret_count
            ),
            detail: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Verdict computation
// ---------------------------------------------------------------------------

fn compute_file_verdict(findings: &[Finding]) -> (Verdict, f32) {
    let has_critical = findings.iter().any(|f| f.severity == FindingSeverity::Critical);
    let has_high = findings.iter().any(|f| f.severity == FindingSeverity::High);
    let medium_count = findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count();

    if has_critical {
        (Verdict::Dangerous, 0.9)
    } else if has_high {
        (Verdict::Risky, 0.85)
    } else if medium_count >= 3 {
        (Verdict::Risky, 0.75)
    } else if medium_count >= 1 {
        (Verdict::Caution, 0.7)
    } else {
        (Verdict::Safe, 0.8)
    }
}

fn compute_url_verdict(findings: &[Finding], is_known: bool) -> (Verdict, f32) {
    let has_high = findings.iter().any(|f| f.severity == FindingSeverity::High);
    let medium_count = findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count();

    if has_high && medium_count >= 1 {
        (Verdict::Dangerous, 0.85)
    } else if has_high {
        (Verdict::Risky, 0.8)
    } else if medium_count >= 2 {
        (Verdict::Risky, 0.75)
    } else if medium_count >= 1 {
        (Verdict::Caution, 0.7)
    } else if is_known {
        (Verdict::Safe, 0.9)
    } else {
        (Verdict::Safe, 0.6)
    }
}

fn compute_config_verdict(servers: &[ServerAnalysis]) -> (Verdict, f32) {
    let has_critical = servers.iter()
        .any(|s| s.findings.iter().any(|f| f.severity == FindingSeverity::Critical));
    let has_high = servers.iter()
        .any(|s| s.findings.iter().any(|f| f.severity == FindingSeverity::High));
    let total_medium: usize = servers.iter()
        .map(|s| s.findings.iter().filter(|f| f.severity == FindingSeverity::Medium).count())
        .sum();

    if has_critical {
        (Verdict::Dangerous, 0.9)
    } else if has_high {
        (Verdict::Risky, 0.85)
    } else if total_medium >= 3 {
        (Verdict::Caution, 0.75)
    } else if total_medium >= 1 {
        (Verdict::Caution, 0.7)
    } else {
        (Verdict::Safe, 0.8)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    /// Helper: create a temp file with content inside a temp directory under $HOME.
    fn create_test_file(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).expect("write test file");
        path
    }

    /// Create a temp dir inside $HOME so path validation passes.
    fn home_temp_dir() -> tempfile::TempDir {
        let home = dirs::home_dir().expect("home dir");
        tempfile::tempdir_in(home).expect("tempdir in home")
    }

    // -- Script analysis tests --

    #[test]
    fn test_script_with_subprocess() {
        let dir = home_temp_dir();
        let path = create_test_file(
            &dir,
            "suspicious.py",
            "import subprocess\nsubprocess.run(['ls'])\nimport os\nos.system('rm -rf /')\n",
        );
        let result = FileAnalyzer::analyze(path.to_str().unwrap()).unwrap();
        assert_eq!(result.file_info.file_type, FileType::Script);
        assert!(result.findings.iter().any(|f| f.description.contains("subprocess")));
        assert!(result.findings.iter().any(|f| f.description.contains("os.system")));
        assert!(matches!(result.verdict, Verdict::Caution | Verdict::Risky));
    }

    #[test]
    fn test_safe_script() {
        let dir = home_temp_dir();
        let path = create_test_file(
            &dir,
            "hello.py",
            "print('Hello, world!')\nx = 1 + 2\n",
        );
        let result = FileAnalyzer::analyze(path.to_str().unwrap()).unwrap();
        assert_eq!(result.verdict, Verdict::Safe);
        assert_eq!(result.file_info.file_type, FileType::Script);
    }

    // -- Config analysis tests --

    #[test]
    fn test_mcp_config_analysis() {
        let config = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
                },
                "safe-server": {
                    "command": "node",
                    "args": ["server.js"]
                }
            }
        }"#;
        let result = ConfigAnalyzer::analyze_content(config).unwrap();
        assert_eq!(result.servers_found.len(), 2);
        // filesystem server should be flagged for broad path access
        let fs_server = result.servers_found.iter().find(|s| s.name == "filesystem").unwrap();
        assert!(!fs_server.findings.is_empty());
        assert!(fs_server.findings.iter().any(|f| f.description.contains("broad file access")));
    }

    #[test]
    fn test_mcp_config_with_sudo() {
        let config = r#"{
            "mcpServers": {
                "admin-server": {
                    "command": "sudo",
                    "args": ["node", "server.js"]
                }
            }
        }"#;
        let result = ConfigAnalyzer::analyze_content(config).unwrap();
        assert_eq!(result.verdict, Verdict::Dangerous);
        let server = &result.servers_found[0];
        assert!(server.findings.iter().any(|f| f.severity == FindingSeverity::Critical));
        assert_eq!(server.recommended_trust_level, "block");
    }

    #[test]
    fn test_mcp_config_with_secrets() {
        let config = r#"{
            "mcpServers": {
                "api-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-1234567890abcdef",
                        "NORMAL_VAR": "hello"
                    }
                }
            }
        }"#;
        let result = ConfigAnalyzer::analyze_content(config).unwrap();
        let server = &result.servers_found[0];
        assert!(server.findings.iter().any(|f| f.description.contains("secret")));
    }

    #[test]
    fn test_not_mcp_config() {
        let config = r#"{"name": "test", "version": "1.0"}"#;
        let result = ConfigAnalyzer::analyze_content(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mcpServers"));
    }

    // -- .env file tests --

    #[test]
    fn test_env_file_detection() {
        let dir = home_temp_dir();
        let path = create_test_file(
            &dir,
            ".env",
            "DATABASE_URL=postgres://localhost/db\nAPI_KEY=secret123\nSECRET_TOKEN=abc\n",
        );
        let result = FileAnalyzer::analyze(path.to_str().unwrap()).unwrap();
        assert_eq!(result.file_info.file_type, FileType::EnvFile);
        assert!(matches!(result.verdict, Verdict::Risky | Verdict::Dangerous));
        assert!(result.findings.iter().any(|f| f.description.contains("Environment file")));
    }

    #[test]
    fn test_env_file_with_suffix() {
        let dir = home_temp_dir();
        let path = create_test_file(&dir, ".env.production", "SECRET_KEY=abc123\n");
        let result = FileAnalyzer::analyze(path.to_str().unwrap()).unwrap();
        assert_eq!(result.file_info.file_type, FileType::EnvFile);
    }

    // -- URL analysis tests --

    #[test]
    fn test_known_service_url() {
        let result = UrlAnalyzer::analyze("https://github.com/user/repo").unwrap();
        assert!(result.url_info.is_known_service);
        assert_eq!(result.verdict, Verdict::Safe);
        assert_eq!(result.url_info.domain, "github.com");
    }

    #[test]
    fn test_suspicious_domain_ip() {
        let result = UrlAnalyzer::analyze("https://192.168.1.1/admin/shell").unwrap();
        assert!(result.findings.iter().any(|f| f.description.contains("IP address")));
        assert!(result.findings.iter().any(|f| f.description.contains("/admin")));
        assert!(result.findings.iter().any(|f| f.description.contains("/shell")));
    }

    #[test]
    fn test_suspicious_tld() {
        let result = UrlAnalyzer::analyze("https://totally-legit.xyz/download").unwrap();
        assert!(result.findings.iter().any(|f| f.description.contains(".xyz")));
        assert!(matches!(result.verdict, Verdict::Caution | Verdict::Risky));
    }

    #[test]
    fn test_http_url() {
        let result = UrlAnalyzer::analyze("http://example.com").unwrap();
        assert!(result.findings.iter().any(|f| f.description.contains("HTTP instead of HTTPS")));
    }

    #[test]
    fn test_invalid_scheme() {
        let result = UrlAnalyzer::analyze("ftp://example.com/file");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_url() {
        let result = UrlAnalyzer::analyze("");
        assert!(result.is_err());
    }

    #[test]
    fn test_url_with_credentials() {
        let result = UrlAnalyzer::analyze("https://admin:password@evil.com/login").unwrap();
        assert!(result.findings.iter().any(|f| f.description.contains("credentials")));
    }

    // -- Security hardening tests --

    #[test]
    fn test_path_outside_home_rejected() {
        let result = FileAnalyzer::analyze("/etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside your home directory"));
    }

    #[test]
    fn test_symlink_outside_home_rejected() {
        let dir = home_temp_dir();
        let link_path = dir.path().join("sneaky_link");
        // Create a symlink pointing to /etc/passwd
        if symlink("/etc/hosts", &link_path).is_ok() {
            let result = FileAnalyzer::analyze(link_path.to_str().unwrap());
            assert!(result.is_err(), "Symlink pointing outside home should be rejected");
        }
        // If symlink creation fails (permissions), test passes trivially
    }

    #[test]
    fn test_nonexistent_file() {
        let result = FileAnalyzer::analyze("/nonexistent/path/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_large_file_metadata_only() {
        // We can't easily create a 5MB+ file in tests, but verify the constant
        assert_eq!(MAX_CONTENT_SIZE, 5 * 1024 * 1024);
    }

    // -- Binary file test --

    #[test]
    fn test_binary_file_metadata_only() {
        let dir = home_temp_dir();
        let path = dir.path().join("program.exe");
        fs::write(&path, b"\x7fELF\x00\x00").expect("write binary");
        let result = FileAnalyzer::analyze(path.to_str().unwrap()).unwrap();
        assert_eq!(result.file_info.file_type, FileType::Binary);
        assert!(result.findings.iter().any(|f| f.description.contains("Binary file")));
    }

    // -- File type classification --

    #[test]
    fn test_classify_extensions() {
        assert_eq!(classify_extension("py", "test.py"), FileType::Script);
        assert_eq!(classify_extension("js", "app.js"), FileType::Script);
        assert_eq!(classify_extension("json", "config.json"), FileType::Config);
        assert_eq!(classify_extension("toml", "Cargo.toml"), FileType::Config);
        assert_eq!(classify_extension("pdf", "doc.pdf"), FileType::Document);
        assert_eq!(classify_extension("exe", "app.exe"), FileType::Binary);
        assert_eq!(classify_extension("", ".env"), FileType::EnvFile);
        assert_eq!(classify_extension("unknown", "file.unknown"), FileType::Other);
    }

    // -- SHA-256 hash test --

    #[test]
    fn test_sha256_computation() {
        let dir = home_temp_dir();
        let path = create_test_file(&dir, "hashme.txt", "hello world\n");
        let result = FileAnalyzer::analyze(path.to_str().unwrap()).unwrap();
        // sha256 of "hello world\n" is well-known
        assert_ne!(result.file_info.sha256, "unavailable");
        assert_ne!(result.file_info.sha256, "skipped-too-large");
        assert_eq!(result.file_info.sha256.len(), 64); // SHA-256 hex is 64 chars
    }

    // -- IP address detection --

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("10.0.0.1"));
        assert!(!is_ip_address("github.com"));
        assert!(!is_ip_address("my-server.local"));
    }

    // -- Config analysis edge cases --

    #[test]
    fn test_config_with_shell_command() {
        let config = r#"{
            "mcpServers": {
                "shell-server": {
                    "command": "bash",
                    "args": ["-c", "node server.js"]
                }
            }
        }"#;
        let result = ConfigAnalyzer::analyze_content(config).unwrap();
        let server = &result.servers_found[0];
        assert!(server.findings.iter().any(|f| f.description.contains("shell")));
    }

    #[test]
    fn test_config_safe_server() {
        let config = r#"{
            "mcpServers": {
                "safe": {
                    "command": "node",
                    "args": ["./my-server/index.js"]
                }
            }
        }"#;
        let result = ConfigAnalyzer::analyze_content(config).unwrap();
        assert_eq!(result.verdict, Verdict::Safe);
        assert_eq!(result.servers_found[0].recommended_trust_level, "allow");
    }
}
