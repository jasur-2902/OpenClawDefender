use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use serde_json::json;
use std::time::Instant;

use crate::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use crate::modules::{ScanContext, ScanModule};

#[derive(Default)]
pub struct ExfiltrationModule;

impl ExfiltrationModule {
    pub fn new() -> Self {
        Self
    }
}

/// Known package registries that are expected network targets.
const KNOWN_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "rubygems.org",
    "repo.maven.apache.org",
    "packagist.org",
    "nuget.org",
    "pkg.go.dev",
    "proxy.golang.org",
];

/// Classify a network connection string. Returns (severity, description).
fn classify_connection(conn: &str) -> (Severity, String) {
    let lower = conn.to_lowercase();
    // Localhost
    if lower.contains("127.0.0.1") || lower.contains("::1") || lower.contains("localhost") {
        return (Severity::Info, "Localhost connection".to_string());
    }
    // Known registries
    for registry in KNOWN_REGISTRIES {
        if lower.contains(registry) {
            return (
                Severity::Low,
                format!("Connection to known registry: {registry}"),
            );
        }
    }
    // DNS port 53 - potential DNS exfiltration
    if lower.contains(":53") || lower.contains("port 53") {
        return (
            Severity::High,
            "Connection on DNS port 53 — potential DNS exfiltration".to_string(),
        );
    }
    // Everything else is suspicious
    (
        Severity::Critical,
        format!("Outbound connection to unknown host: {conn}"),
    )
}

/// Check for stack trace patterns in text.
fn contains_stack_trace(text: &str) -> bool {
    let patterns = [
        r"at Object\.",
        r"Error:.*\n.*at ",
        r"at .+:\d+:\d+",
        r"Traceback \(most recent call last\)",
        r#"File ".+", line \d+"#,
        r"panic!?\(",
        r"thread '.+' panicked at",
    ];
    for pat in &patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(text) {
                return true;
            }
        }
    }
    false
}

/// Check for leaked file paths in text.
fn contains_file_path_leak(text: &str) -> bool {
    let patterns = [
        r"/Users/[a-zA-Z0-9_]+/",
        r"/home/[a-zA-Z0-9_]+/",
        r"C:\\Users\\[a-zA-Z0-9_]+\\",
        r"ENOENT",
    ];
    for pat in &patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(text) {
                return true;
            }
        }
    }
    false
}

/// Check for environment variable leakage in text.
fn contains_env_var_leak(text: &str) -> bool {
    let patterns = [
        r"(?i)aws_secret_access_key\s*=",
        r"(?i)aws_access_key_id\s*=",
        r"(?i)database_url\s*=",
        r"(?i)db_password\s*=",
        r"(?i)secret_key\s*=",
        r"(?i)api_key\s*=",
        r"(?i)private_key\s*=",
    ];
    for pat in &patterns {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(text) {
                return true;
            }
        }
    }
    false
}

/// Check for DNS exfiltration patterns in a domain string.
fn is_dns_exfiltration_pattern(domain: &str) -> bool {
    // Long encoded subdomain pattern
    if let Ok(re) = Regex::new(r"[a-zA-Z0-9]{20,}\.[a-z]+\.[a-z]+") {
        if re.is_match(domain) {
            return true;
        }
    }
    // Base64-like patterns in subdomains
    if let Ok(re) = Regex::new(r"[A-Za-z0-9+/=]{16,}\.[a-z]+") {
        if re.is_match(domain) {
            return true;
        }
    }
    false
}

/// Analyze timing measurements for side-channel leakage.
/// Returns true if average difference exceeds threshold_ms.
fn has_timing_oracle(
    existing_times_ms: &[f64],
    missing_times_ms: &[f64],
    threshold_ms: f64,
) -> bool {
    if existing_times_ms.is_empty() || missing_times_ms.is_empty() {
        return false;
    }
    let avg_existing: f64 = existing_times_ms.iter().sum::<f64>() / existing_times_ms.len() as f64;
    let avg_missing: f64 = missing_times_ms.iter().sum::<f64>() / missing_times_ms.len() as f64;
    (avg_existing - avg_missing).abs() > threshold_ms
}

#[async_trait]
impl ScanModule for ExfiltrationModule {
    fn name(&self) -> &str {
        "exfiltration"
    }

    fn description(&self) -> &str {
        "Tests for data exfiltration, network attacks, and information leakage"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DataExfiltration
    }

    async fn run(&self, ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut finding_counter = 0u32;

        let next_id = |counter: &mut u32| -> String {
            *counter += 1;
            format!("EXFIL-{:03}", counter)
        };

        // ------------------------------------------------------------------
        // 1. Network connection monitoring
        // ------------------------------------------------------------------
        let connections: Vec<String> = ctx.evidence.network_connections().to_vec();
        for conn in &connections {
            let (severity, desc) = classify_connection(conn);
            match severity {
                Severity::Info => {} // skip informational localhost
                Severity::Low => {}  // skip known registries
                _ => {
                    let cvss = match severity {
                        Severity::Critical => 9.0,
                        Severity::High => 7.5,
                        _ => 5.0,
                    };
                    findings.push(Finding {
                        id: next_id(&mut finding_counter),
                        title: "Suspicious outbound network connection".to_string(),
                        severity,
                        cvss,
                        category: ModuleCategory::DataExfiltration,
                        description: desc,
                        reproduction: None,
                        evidence: Evidence {
                            network_connections: vec![conn.clone()],
                            ..Evidence::empty()
                        },
                        remediation: "Restrict outbound network access from the MCP server process. Use network sandboxing or firewall rules.".to_string(),
                    });
                }
            }
        }

        // ------------------------------------------------------------------
        // 2. Response data leakage testing
        // ------------------------------------------------------------------
        // 2a. Error message info leakage — call tools with invalid args
        for tool in &ctx.tool_list.clone() {
            let invalid_args = json!({"__invalid_field__": true, "wrong_type": 12345});
            let resp = ctx
                .client
                .call_tool_raw(&tool.name, invalid_args.clone())
                .await;
            if let Ok(val) = resp {
                let text = val.to_string();

                // Stack trace detection
                if contains_stack_trace(&text) {
                    findings.push(Finding {
                        id: next_id(&mut finding_counter),
                        title: format!("Stack trace leaked in error from tool '{}'", tool.name),
                        severity: Severity::Medium,
                        cvss: 4.5,
                        category: ModuleCategory::DataExfiltration,
                        description: "Error responses contain stack traces that reveal internal implementation details.".to_string(),
                        reproduction: Some(Reproduction {
                            method: "Call tool with invalid arguments".to_string(),
                            tool: Some(tool.name.clone()),
                            arguments: Some(invalid_args.clone()),
                        }),
                        evidence: Evidence {
                            messages: vec![ctx.client.history().len().saturating_sub(1)],
                            ..Evidence::empty()
                        },
                        remediation: "Sanitize error messages before returning them. Remove stack traces and internal paths from error responses.".to_string(),
                    });
                }

                // File path leak detection
                if contains_file_path_leak(&text) {
                    findings.push(Finding {
                        id: next_id(&mut finding_counter),
                        title: format!("File path leaked in error from tool '{}'", tool.name),
                        severity: Severity::Medium,
                        cvss: 4.5,
                        category: ModuleCategory::DataExfiltration,
                        description: "Error responses contain full file system paths revealing directory structure.".to_string(),
                        reproduction: Some(Reproduction {
                            method: "Call tool with invalid arguments".to_string(),
                            tool: Some(tool.name.clone()),
                            arguments: Some(invalid_args.clone()),
                        }),
                        evidence: Evidence {
                            messages: vec![ctx.client.history().len().saturating_sub(1)],
                            ..Evidence::empty()
                        },
                        remediation: "Strip absolute file paths from error messages. Use relative paths or generic descriptions.".to_string(),
                    });
                }

                // Env var leakage detection
                if contains_env_var_leak(&text) {
                    findings.push(Finding {
                        id: next_id(&mut finding_counter),
                        title: format!("Environment variable leaked in error from tool '{}'", tool.name),
                        severity: Severity::High,
                        cvss: 7.0,
                        category: ModuleCategory::DataExfiltration,
                        description: "Error responses contain environment variable values including potential secrets.".to_string(),
                        reproduction: Some(Reproduction {
                            method: "Call tool with invalid arguments".to_string(),
                            tool: Some(tool.name.clone()),
                            arguments: Some(invalid_args),
                        }),
                        evidence: Evidence {
                            messages: vec![ctx.client.history().len().saturating_sub(1)],
                            ..Evidence::empty()
                        },
                        remediation: "Never include environment variable values in error messages. Sanitize all output.".to_string(),
                    });
                }
            }
        }

        // 2c. Environment variable expansion via tool arguments
        let env_test_strings = [
            "$HOME",
            "$PATH",
            "$AWS_SECRET_ACCESS_KEY",
            "${HOME}",
            "${SECRET_KEY}",
        ];
        for tool in &ctx.tool_list.clone() {
            for env_str in &env_test_strings {
                let args = json!({"path": env_str, "input": env_str});
                if let Ok(val) = ctx.client.call_tool_raw(&tool.name, args).await {
                    let text = val.to_string();
                    // If the response contains an expanded path (not the literal $VAR), it leaked
                    if !text.contains(env_str)
                        && (text.contains("/Users/")
                            || text.contains("/home/")
                            || text.contains("/root"))
                    {
                        findings.push(Finding {
                            id: next_id(&mut finding_counter),
                            title: format!("Environment variable expansion in tool '{}'", tool.name),
                            severity: Severity::High,
                            cvss: 7.0,
                            category: ModuleCategory::DataExfiltration,
                            description: format!(
                                "Tool '{}' expands environment variable references ({}) in arguments, potentially leaking secrets.",
                                tool.name, env_str
                            ),
                            reproduction: Some(Reproduction {
                                method: "Pass env var reference in arguments".to_string(),
                                tool: Some(tool.name.clone()),
                                arguments: Some(json!({"input": env_str})),
                            }),
                            evidence: Evidence {
                                messages: vec![ctx.client.history().len().saturating_sub(1)],
                                ..Evidence::empty()
                            },
                            remediation: "Do not expand environment variables in tool arguments. Treat all input as literal strings.".to_string(),
                        });
                        break; // one finding per tool is enough
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // 3. Side-channel testing
        // ------------------------------------------------------------------
        // Find a file-read tool if available
        let file_tools: Vec<String> = ctx
            .tool_list
            .iter()
            .filter(|t| {
                let lower = t.name.to_lowercase();
                lower.contains("read") || lower.contains("file") || lower.contains("get")
            })
            .map(|t| t.name.clone())
            .collect();

        if let Some(file_tool) = file_tools.first() {
            // 3a. Timing side channel
            let mut existing_times = Vec::new();
            let mut missing_times = Vec::new();

            let existing_path = ctx.sandbox.home().join(".env");
            let missing_path = ctx.sandbox.home().join("nonexistent_file_timing_test.txt");

            for _ in 0..10 {
                let start = Instant::now();
                let _ = ctx
                    .client
                    .call_tool_raw(
                        file_tool,
                        json!({"path": existing_path.to_string_lossy().to_string()}),
                    )
                    .await;
                existing_times.push(start.elapsed().as_secs_f64() * 1000.0);

                let start = Instant::now();
                let _ = ctx
                    .client
                    .call_tool_raw(
                        file_tool,
                        json!({"path": missing_path.to_string_lossy().to_string()}),
                    )
                    .await;
                missing_times.push(start.elapsed().as_secs_f64() * 1000.0);
            }

            if has_timing_oracle(&existing_times, &missing_times, 100.0) {
                findings.push(Finding {
                    id: next_id(&mut finding_counter),
                    title: "Timing oracle detected in file access".to_string(),
                    severity: Severity::Low,
                    cvss: 3.5,
                    category: ModuleCategory::DataExfiltration,
                    description: format!(
                        "File read tool '{}' shows >100ms timing difference between existing and non-existing files, enabling file enumeration.",
                        file_tool
                    ),
                    reproduction: Some(Reproduction {
                        method: "Compare response times for existing vs missing files".to_string(),
                        tool: Some(file_tool.clone()),
                        arguments: None,
                    }),
                    evidence: Evidence::empty(),
                    remediation: "Normalize response times for file operations regardless of whether the file exists.".to_string(),
                });
            }

            // 3b. Error message differential
            let resp_missing = ctx
                .client
                .call_tool_raw(
                    file_tool,
                    json!({"path": missing_path.to_string_lossy().to_string()}),
                )
                .await;
            let resp_denied = ctx
                .client
                .call_tool_raw(file_tool, json!({"path": "/etc/shadow"}))
                .await;

            if let (Ok(missing_val), Ok(denied_val)) = (resp_missing, resp_denied) {
                let missing_text = missing_val.to_string();
                let denied_text = denied_val.to_string();
                // If messages are substantially different, report it
                if missing_text != denied_text
                    && !missing_text.is_empty()
                    && !denied_text.is_empty()
                {
                    // Check for different error types
                    let missing_has_notfound = missing_text.contains("not found")
                        || missing_text.contains("ENOENT")
                        || missing_text.contains("No such file");
                    let denied_has_permission = denied_text.contains("permission")
                        || denied_text.contains("EACCES")
                        || denied_text.contains("denied");

                    if missing_has_notfound || denied_has_permission {
                        findings.push(Finding {
                            id: next_id(&mut finding_counter),
                            title: "Error message differential enables file enumeration".to_string(),
                            severity: Severity::Low,
                            cvss: 3.0,
                            category: ModuleCategory::DataExfiltration,
                            description: "Different error messages for 'not found' vs 'permission denied' allow an attacker to enumerate existing files.".to_string(),
                            reproduction: Some(Reproduction {
                                method: "Compare error messages for missing vs permission-denied files".to_string(),
                                tool: Some(file_tool.clone()),
                                arguments: None,
                            }),
                            evidence: Evidence {
                                messages: vec![
                                    ctx.client.history().len().saturating_sub(2),
                                    ctx.client.history().len().saturating_sub(1),
                                ],
                                ..Evidence::empty()
                            },
                            remediation: "Return uniform error messages for all file access failures. Do not distinguish between missing and forbidden.".to_string(),
                        });
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // 4. DNS exfiltration detection
        // ------------------------------------------------------------------
        for conn in &connections {
            // Check for port 53 connections
            if conn.contains(":53") || conn.to_lowercase().contains("port 53") {
                // Extract domain part and check for exfiltration patterns
                if is_dns_exfiltration_pattern(conn) {
                    findings.push(Finding {
                        id: next_id(&mut finding_counter),
                        title: "Potential DNS exfiltration detected".to_string(),
                        severity: Severity::Critical,
                        cvss: 9.5,
                        category: ModuleCategory::DataExfiltration,
                        description: format!(
                            "Suspicious DNS query with encoded data pattern detected: {}",
                            conn
                        ),
                        reproduction: None,
                        evidence: Evidence {
                            network_connections: vec![conn.clone()],
                            ..Evidence::empty()
                        },
                        remediation: "Block DNS queries with unusually long subdomains. Monitor for base64-encoded data in DNS labels.".to_string(),
                    });
                }
            }
            // Also check non-port-53 connections for DNS exfiltration patterns
            if is_dns_exfiltration_pattern(conn) && !conn.contains(":53") {
                findings.push(Finding {
                    id: next_id(&mut finding_counter),
                    title: "Suspicious domain pattern in network connection".to_string(),
                    severity: Severity::High,
                    cvss: 8.0,
                    category: ModuleCategory::DataExfiltration,
                    description: format!(
                        "Network connection to domain with encoded data pattern: {}",
                        conn
                    ),
                    reproduction: None,
                    evidence: Evidence {
                        network_connections: vec![conn.clone()],
                        ..Evidence::empty()
                    },
                    remediation: "Investigate domains with unusually long or encoded subdomains."
                        .to_string(),
                });
            }
        }

        // ------------------------------------------------------------------
        // 5. Canary monitoring
        // ------------------------------------------------------------------
        let canary_strings = ctx.sandbox.canary_strings();
        for (idx, (_direction, msg)) in ctx.client.history().iter().enumerate() {
            let detected = ctx.evidence.check_canary_in_message(msg, &canary_strings);
            if !detected.is_empty() {
                for canary in &detected {
                    ctx.evidence.record_canary_detection(canary.clone());
                }
                findings.push(Finding {
                    id: next_id(&mut finding_counter),
                    title: "Canary data detected in MCP traffic".to_string(),
                    severity: Severity::Critical,
                    cvss: 9.8,
                    category: ModuleCategory::DataExfiltration,
                    description: format!(
                        "Canary string(s) found in message at index {}: {:?}. This indicates sensitive data exfiltration.",
                        idx, detected
                    ),
                    reproduction: None,
                    evidence: Evidence {
                        messages: vec![idx],
                        canary_detected: true,
                        ..Evidence::empty()
                    },
                    remediation: "The server is leaking sensitive file contents. Restrict file access scope and apply content filtering.".to_string(),
                });
            }
        }

        Ok(findings)
    }
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_connection_localhost_ipv4() {
        let (sev, _desc) = classify_connection("127.0.0.1:8080");
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn test_classify_connection_localhost_ipv6() {
        let (sev, _desc) = classify_connection("::1:3000");
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn test_classify_connection_localhost_name() {
        let (sev, _desc) = classify_connection("localhost:9090");
        assert_eq!(sev, Severity::Info);
    }

    #[test]
    fn test_classify_connection_known_registry() {
        let (sev, _desc) = classify_connection("registry.npmjs.org:443");
        assert_eq!(sev, Severity::Low);

        let (sev2, _) = classify_connection("pypi.org:443");
        assert_eq!(sev2, Severity::Low);

        let (sev3, _) = classify_connection("crates.io:443");
        assert_eq!(sev3, Severity::Low);
    }

    #[test]
    fn test_classify_connection_external_host() {
        let (sev, _desc) = classify_connection("evil-server.com:443");
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn test_classify_connection_dns_port() {
        let (sev, _desc) = classify_connection("8.8.8.8:53");
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn test_contains_stack_trace_js() {
        assert!(contains_stack_trace(
            "Error: something failed\n    at Object.method (/src/index.js:10:5)"
        ));
        assert!(contains_stack_trace("at Object.create"));
    }

    #[test]
    fn test_contains_stack_trace_python() {
        assert!(contains_stack_trace("Traceback (most recent call last)"));
    }

    #[test]
    fn test_contains_stack_trace_rust() {
        assert!(contains_stack_trace("thread 'main' panicked at 'error'"));
    }

    #[test]
    fn test_contains_stack_trace_negative() {
        assert!(!contains_stack_trace("Everything is fine, no errors here."));
        assert!(!contains_stack_trace(""));
    }

    #[test]
    fn test_contains_file_path_leak_unix() {
        assert!(contains_file_path_leak("/Users/jasur/project/src/main.rs"));
        assert!(contains_file_path_leak("/home/user/.config/settings"));
    }

    #[test]
    fn test_contains_file_path_leak_enoent() {
        assert!(contains_file_path_leak("ENOENT: no such file"));
    }

    #[test]
    fn test_contains_file_path_leak_negative() {
        assert!(!contains_file_path_leak("file not found"));
        assert!(!contains_file_path_leak("some normal text"));
    }

    #[test]
    fn test_contains_env_var_leak() {
        assert!(contains_env_var_leak(
            "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE"
        ));
        assert!(contains_env_var_leak(
            "DATABASE_URL= postgres://user:pass@host/db"
        ));
        assert!(contains_env_var_leak("API_KEY= sk-12345"));
    }

    #[test]
    fn test_contains_env_var_leak_negative() {
        assert!(!contains_env_var_leak("No secrets here"));
        assert!(!contains_env_var_leak("just a normal response"));
    }

    #[test]
    fn test_dns_exfiltration_pattern_long_subdomain() {
        assert!(is_dns_exfiltration_pattern(
            "aGVsbG93b3JsZHRoaXNpc2V4ZmlsdHJhdGlvbg.evil.com"
        ));
    }

    #[test]
    fn test_dns_exfiltration_pattern_normal_domain() {
        assert!(!is_dns_exfiltration_pattern("www.google.com"));
        assert!(!is_dns_exfiltration_pattern("api.github.com"));
    }

    #[test]
    fn test_dns_exfiltration_pattern_base64() {
        assert!(is_dns_exfiltration_pattern("SGVsbG8gV29ybGQhIFRo.evil.com"));
    }

    #[test]
    fn test_has_timing_oracle_significant() {
        let existing = vec![50.0, 55.0, 48.0, 52.0, 51.0];
        let missing = vec![200.0, 195.0, 210.0, 205.0, 198.0];
        assert!(has_timing_oracle(&existing, &missing, 100.0));
    }

    #[test]
    fn test_has_timing_oracle_no_difference() {
        let existing = vec![50.0, 55.0, 48.0, 52.0, 51.0];
        let missing = vec![53.0, 49.0, 55.0, 50.0, 52.0];
        assert!(!has_timing_oracle(&existing, &missing, 100.0));
    }

    #[test]
    fn test_has_timing_oracle_empty_data() {
        assert!(!has_timing_oracle(&[], &[100.0], 100.0));
        assert!(!has_timing_oracle(&[100.0], &[], 100.0));
    }

    #[test]
    fn test_finding_severity_network_external() {
        let (sev, _) = classify_connection("attacker.example.com:8443");
        assert_eq!(sev, Severity::Critical);
    }

    #[test]
    fn test_finding_severity_stack_trace() {
        // Stack trace findings get Medium
        assert!(contains_stack_trace(
            "at Object.run (/app/src/handler.js:42:13)"
        ));
    }

    #[test]
    fn test_module_metadata() {
        let module = ExfiltrationModule::new();
        assert_eq!(module.name(), "exfiltration");
        assert_eq!(module.category(), ModuleCategory::DataExfiltration);
        assert!(!module.description().is_empty());
    }

    #[test]
    fn test_error_differential_patterns() {
        // Simulating what the analysis looks for
        let not_found_msg = r#"{"error": "ENOENT: no such file or directory"}"#;
        let permission_msg = r#"{"error": "EACCES: permission denied"}"#;

        assert!(not_found_msg.contains("ENOENT"));
        assert!(permission_msg.contains("EACCES"));
        assert_ne!(not_found_msg, permission_msg);
    }
}
