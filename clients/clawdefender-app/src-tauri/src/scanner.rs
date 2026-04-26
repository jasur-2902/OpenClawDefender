//! Comprehensive multi-module security scanner for RookBot.
//!
//! Runs 11 scanner modules in-process:
//! 1. MCP Configuration Audit
//! 2. Policy Strength Analysis
//! 3. Server Reputation Check
//! 4. System Security Posture
//! 5. Behavioral Anomaly Review
//! 6. TCC Permission Audit
//! 7. File Integrity Monitor
//! 8. Clipboard Security Check
//! 9. Process Memory Scan
//! 10. CIS Benchmark Compliance
//! 11. Browser Extension Audit

use crate::commands::{mcp_config_paths, extract_servers};
use crate::state::{ScanFinding, ScanFixAction, ScanModuleResult};
use std::path::{Path, PathBuf};

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Module 1: MCP Configuration Audit
// ---------------------------------------------------------------------------

pub fn scan_mcp_configs() -> ScanModuleResult {
    let home = home_dir().unwrap_or_default();
    let mut findings = Vec::new();

    for (config_path, client_id, client_name) in mcp_config_paths() {
        let contents = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => {
                findings.push(ScanFinding {
                    severity: "high".to_string(),
                    category: "mcp-config".to_string(),
                    module: "mcp-config-audit".to_string(),
                    description: format!(
                        "{} config at {} contains malformed JSON",
                        client_name,
                        config_path.display()
                    ),
                    affected_resource: config_path.to_string_lossy().to_string(),
                    fix_suggestion: "Fix the JSON syntax in the configuration file".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
                continue;
            }
        };

        let servers = match extract_servers(&config) {
            Some(obj) => obj,
            None => continue,
        };

        for (server_name, entry) in servers {
            let wrapped = entry.get("_clawdefender_original").is_some()
                || entry.get("_clawai_original").is_some();

            // Extract command args for path analysis
            let args: Vec<String> = entry
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // Check for sensitive path exposure
            let sensitive_paths = check_sensitive_paths(&args, &home);

            if !wrapped && !sensitive_paths.is_empty() {
                // CRITICAL: unwrapped + sensitive paths
                findings.push(ScanFinding {
                    severity: "critical".to_string(),
                    category: "mcp-config".to_string(),
                    module: "mcp-config-audit".to_string(),
                    description: format!(
                        "Server '{}' in {} is NOT wrapped by RookBot AND exposes sensitive paths: {}",
                        server_name,
                        client_name,
                        sensitive_paths.join(", ")
                    ),
                    affected_resource: format!("{}:{}", client_name, server_name),
                    fix_suggestion: format!(
                        "Wrap server '{}' with RookBot and restrict path access",
                        server_name
                    ),
                    fix_action: Some(ScanFixAction {
                        action_type: "wrap_server".to_string(),
                        client: Some(client_id.to_string()),
                        server: Some(server_name.clone()),
                        rule_name: None,
                        rule_resource: None,
                        rule_action: None,
                    }),
                    ai_analysis: None,
                });
            } else if !wrapped {
                // HIGH: unwrapped server
                findings.push(ScanFinding {
                    severity: "high".to_string(),
                    category: "mcp-config".to_string(),
                    module: "mcp-config-audit".to_string(),
                    description: format!(
                        "Server '{}' in {} is NOT wrapped by RookBot",
                        server_name, client_name
                    ),
                    affected_resource: format!("{}:{}", client_name, server_name),
                    fix_suggestion: format!(
                        "Wrap server '{}' to enable security monitoring and policy enforcement",
                        server_name
                    ),
                    fix_action: Some(ScanFixAction {
                        action_type: "wrap_server".to_string(),
                        client: Some(client_id.to_string()),
                        server: Some(server_name.clone()),
                        rule_name: None,
                        rule_resource: None,
                        rule_action: None,
                    }),
                    ai_analysis: None,
                });
            } else if !sensitive_paths.is_empty() {
                // HIGH: wrapped but exposes sensitive paths
                findings.push(ScanFinding {
                    severity: "high".to_string(),
                    category: "mcp-config".to_string(),
                    module: "mcp-config-audit".to_string(),
                    description: format!(
                        "Server '{}' in {} exposes sensitive paths: {}",
                        server_name,
                        client_name,
                        sensitive_paths.join(", ")
                    ),
                    affected_resource: format!("{}:{}", client_name, server_name),
                    fix_suggestion:
                        "Restrict the server's filesystem access to project directories only"
                            .to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }

            // Check for overly broad filesystem access
            let broad_paths = check_broad_paths(&args, &home);
            if !broad_paths.is_empty() {
                findings.push(ScanFinding {
                    severity: if wrapped { "medium" } else { "high" }.to_string(),
                    category: "mcp-config".to_string(),
                    module: "mcp-config-audit".to_string(),
                    description: format!(
                        "Server '{}' in {} has overly broad filesystem access: {}",
                        server_name,
                        client_name,
                        broad_paths.join(", ")
                    ),
                    affected_resource: format!("{}:{}", client_name, server_name),
                    fix_suggestion:
                        "Restrict to specific project directories instead of home or root"
                            .to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }
        }
    }

    let summary = if findings.is_empty() {
        "All MCP server configurations look good".to_string()
    } else {
        format!(
            "Found {} issue{} across MCP client configurations",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        )
    };

    ScanModuleResult {
        module_id: "mcp-config-audit".to_string(),
        module_name: "MCP Configuration Audit".to_string(),
        status: "completed".to_string(),
        findings,
        summary,
    }
}

fn check_sensitive_paths(args: &[String], _home: &Path) -> Vec<String> {
    let sensitive_patterns = [
        "/.ssh",
        "/.aws",
        "/.gnupg",
        "/.kube",
        "/.config/gcloud",
        "/.azure",
        "/Library/Keychains",
        "/.password-store",
        "/.docker",
        "/.netrc",
        "/etc/shadow",
        "/etc/passwd",
    ];

    let mut found = Vec::new();
    for arg in args {
        for pat in &sensitive_patterns {
            if arg.contains(pat) {
                found.push(arg.clone());
                break;
            }
        }
    }
    found
}

fn check_broad_paths(args: &[String], home: &Path) -> Vec<String> {
    let home_str = home.to_string_lossy();
    let mut found = Vec::new();
    for arg in args {
        // Check if it looks like a path
        if !arg.starts_with('/') && !arg.starts_with('~') {
            continue;
        }
        let expanded = arg.replace('~', &home_str);
        // Flag root, home dir root, or system directories as overly broad
        if expanded == "/"
            || expanded == *home_str
            || expanded == format!("{}/", home_str)
            || expanded.starts_with("/usr")
            || expanded.starts_with("/System")
            || expanded.starts_with("/Library")
            || expanded == "/etc"
            || expanded == "/var"
            || expanded == "/tmp"
        {
            found.push(arg.clone());
        }
    }
    found
}



// ---------------------------------------------------------------------------
// Module 2: Policy Strength Analysis
// ---------------------------------------------------------------------------

pub fn scan_policy_strength() -> ScanModuleResult {
    let home = home_dir().unwrap_or_default();
    let policy_path = home.join(".config/rookbot/policy.toml");
    let mut findings = Vec::new();

    if !policy_path.exists() {
        findings.push(ScanFinding {
            severity: "high".to_string(),
            category: "policy".to_string(),
            module: "policy-strength".to_string(),
            description: "No policy file found. All operations are uncontrolled.".to_string(),
            affected_resource: policy_path.to_string_lossy().to_string(),
            fix_suggestion: "Apply a security template from the Policy page to establish baseline rules".to_string(),
            fix_action: None,
            ai_analysis: None,
        });

        return ScanModuleResult {
            module_id: "policy-strength".to_string(),
            module_name: "Policy Strength Analysis".to_string(),
            status: "completed".to_string(),
            findings,
            summary: "No policy file found - security posture is weak".to_string(),
        };
    }

    let contents = match std::fs::read_to_string(&policy_path) {
        Ok(c) => c,
        Err(e) => {
            findings.push(ScanFinding {
                severity: "high".to_string(),
                category: "policy".to_string(),
                module: "policy-strength".to_string(),
                description: format!("Cannot read policy file: {}", e),
                affected_resource: policy_path.to_string_lossy().to_string(),
                fix_suggestion: "Check file permissions on the policy file".to_string(),
                fix_action: None,
                ai_analysis: None,
            });
            return ScanModuleResult {
                module_id: "policy-strength".to_string(),
                module_name: "Policy Strength Analysis".to_string(),
                status: "completed".to_string(),
                findings,
                summary: "Policy file unreadable".to_string(),
            };
        }
    };

    // Check for credential file protections
    let credential_paths = [
        ("SSH keys", "~/.ssh/id_*"),
        ("AWS credentials", "~/.aws/credentials"),
        ("GPG keys", "~/.gnupg/*"),
        ("Kubernetes config", "~/.kube/config"),
        ("Docker config", "~/.docker/config.json"),
        ("GCloud credentials", "~/.config/gcloud/*"),
        ("Azure credentials", "~/.azure/*"),
        ("Browser passwords", "*/Login Data"),
        ("Keychain", "*/Keychains/*"),
        (".env files", "**/.env"),
        ("netrc", "~/.netrc"),
    ];

    for (name, pattern) in &credential_paths {
        if !contents.contains(pattern) && !contents.contains(&pattern.replace("~", &home.to_string_lossy())) {
            findings.push(ScanFinding {
                severity: "medium".to_string(),
                category: "policy".to_string(),
                module: "policy-strength".to_string(),
                description: format!(
                    "No policy rule protecting {} ({})",
                    name, pattern
                ),
                affected_resource: format!("policy:{}", pattern),
                fix_suggestion: format!(
                    "Add a 'block' or 'prompt' rule for resource_path = [\"{}\"]",
                    pattern
                ),
                fix_action: Some(ScanFixAction {
                    action_type: "add_policy_rule".to_string(),
                    client: None,
                    server: None,
                    rule_name: Some(format!("protect_{}", name.to_lowercase().replace(' ', "_"))),
                    rule_resource: Some(pattern.to_string()),
                    rule_action: Some("block".to_string()),
                }),
                ai_analysis: None,
            });
        }
    }

    // Check system file protections
    let system_paths = [
        ("System configuration", "/etc/*"),
        ("System binaries", "/usr/bin/*"),
        ("System libraries", "/usr/lib/*"),
        ("LaunchAgents", "~/Library/LaunchAgents/*"),
        ("LaunchDaemons", "/Library/LaunchDaemons/*"),
        ("Crontab", "/var/spool/cron/*"),
    ];

    for (name, pattern) in &system_paths {
        if !contents.contains(pattern) {
            findings.push(ScanFinding {
                severity: "medium".to_string(),
                category: "policy".to_string(),
                module: "policy-strength".to_string(),
                description: format!(
                    "No policy rule protecting {} ({})",
                    name, pattern
                ),
                affected_resource: format!("policy:{}", pattern),
                fix_suggestion: format!(
                    "Add a 'block' or 'prompt' rule for resource_path = [\"{}\"]",
                    pattern
                ),
                fix_action: Some(ScanFixAction {
                    action_type: "add_policy_rule".to_string(),
                    client: None,
                    server: None,
                    rule_name: Some(format!("protect_{}", name.to_lowercase().replace(' ', "_"))),
                    rule_resource: Some(pattern.to_string()),
                    rule_action: Some("block".to_string()),
                }),
                ai_analysis: None,
            });
        }
    }

    // Check for catch-all / overly broad allow rules
    if contents.contains("any = true") {
        // Check if the any=true rule has action = allow
        let lines: Vec<&str> = contents.lines().collect();
        let mut in_any_rule = false;
        let mut any_rule_name = String::new();
        for line in &lines {
            let trimmed = line.trim();
            if trimmed.starts_with("[rules.") && trimmed.ends_with(']') && !trimmed.contains(".match") {
                any_rule_name = trimmed.trim_start_matches("[rules.").trim_end_matches(']').to_string();
            }
            if trimmed == "any = true" {
                in_any_rule = true;
            }
            if in_any_rule && trimmed.starts_with("action") && trimmed.contains("allow") {
                findings.push(ScanFinding {
                    severity: "high".to_string(),
                    category: "policy".to_string(),
                    module: "policy-strength".to_string(),
                    description: format!(
                        "Rule '{}' uses 'any = true' with 'allow' action - this permits ALL operations",
                        any_rule_name
                    ),
                    affected_resource: format!("policy:rule:{}", any_rule_name),
                    fix_suggestion: "Remove the catch-all allow rule or change its action to 'audit'".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
                in_any_rule = false;
            }
            if in_any_rule && trimmed.starts_with('[') {
                in_any_rule = false;
            }
        }
    }

    // Check if policy has any rules at all
    let rule_count = contents.matches("[rules.").count();
    if rule_count == 0 {
        findings.push(ScanFinding {
            severity: "high".to_string(),
            category: "policy".to_string(),
            module: "policy-strength".to_string(),
            description: "Policy file exists but contains no rules".to_string(),
            affected_resource: policy_path.to_string_lossy().to_string(),
            fix_suggestion: "Apply a security template to establish baseline protection".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    } else if rule_count < 5 {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "policy".to_string(),
            module: "policy-strength".to_string(),
            description: format!("Policy has only {} rule(s) - consider adding more comprehensive coverage", rule_count),
            affected_resource: policy_path.to_string_lossy().to_string(),
            fix_suggestion: "Apply the 'strict' template for comprehensive protection".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    let summary = if findings.is_empty() {
        "Policy configuration is strong".to_string()
    } else {
        let critical = findings.iter().filter(|f| f.severity == "critical" || f.severity == "high").count();
        format!(
            "{} policy issue{} found ({} high/critical)",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" },
            critical
        )
    };

    ScanModuleResult {
        module_id: "policy-strength".to_string(),
        module_name: "Policy Strength Analysis".to_string(),
        status: "completed".to_string(),
        findings,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Module 3: Server Reputation Check
// ---------------------------------------------------------------------------

pub fn scan_server_reputation() -> ScanModuleResult {
    let home = home_dir().unwrap_or_default();
    let mut findings = Vec::new();

    // Known suspicious/flagged MCP server packages
    const SUSPICIOUS_PACKAGES: &[&str] = &[
        "mcp-server-everything",
        "mcp-server-shell-exec",
        "mcp-shell-unlimited",
        "mcp-server-cmd",
        "mcp-server-terminal",
        "mcp-unrestricted",
        "mcp-server-admin",
        "mcp-root-access",
        "mcp-server-sudo",
        "mcp-backdoor",
    ];

    // Well-known legitimate packages used for typosquat similarity checks
    const KNOWN_POPULAR: &[&str] = &[
        "mcp-server-filesystem",
        "mcp-server-github",
        "mcp-server-postgres",
        "mcp-server-sqlite",
        "mcp-server-puppeteer",
        "mcp-server-brave-search",
        "mcp-server-memory",
        "mcp-server-fetch",
        "mcp-server-slack",
        "mcp-server-google-maps",
        "mcp-server-sequential-thinking",
    ];

    // Dangerous argument patterns
    const DANGEROUS_ARGS: &[&str] = &[
        "--allow-all",
        "--no-sandbox",
        "--disable-security",
        "--unrestricted",
        "--privileged",
        "--allow-write-all",
    ];

    // Dangerous command fragments indicating code execution
    const DANGEROUS_CMD_FRAGMENTS: &[&str] = &[
        "eval",
        "exec",
        "spawn",
        "child_process",
        "shell_exec",
        "os.system",
        "subprocess",
    ];

    // Load blocklist entries from threat intel feed
    let blocklist_path = home.join(".local/share/rookbot/threat_intel/blocklist.json");
    let blocklist_entries = load_blocklist_entries(&blocklist_path);

    let mut servers_checked = 0u32;

    for (config_path, _client_id, client_name) in mcp_config_paths() {
        let contents = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let config: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let servers = match extract_servers(&config) {
            Some(obj) => obj,
            None => continue,
        };

        for (server_name, entry) in servers {
            servers_checked += 1;

            let command = entry
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args: Vec<&str> = entry
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let full_command = format!("{} {}", command, args.join(" "));

            // --- Check against known suspicious packages ---
            for suspicious in SUSPICIOUS_PACKAGES {
                if full_command.contains(suspicious) || server_name.contains(suspicious) {
                    findings.push(ScanFinding {
                        severity: "high".to_string(),
                        category: "reputation".to_string(),
                        module: "server-reputation".to_string(),
                        description: format!(
                            "Server '{}' in {} matches known suspicious package: {}",
                            server_name, client_name, suspicious
                        ),
                        affected_resource: format!("{}:{}", client_name, server_name),
                        fix_suggestion: format!(
                            "Remove or replace '{}' with a verified alternative",
                            suspicious
                        ),
                        fix_action: None,
                        ai_analysis: None,
                    });
                }
            }

            // --- Check against threat intel blocklist ---
            for blocked in &blocklist_entries {
                if full_command.contains(blocked.as_str())
                    || server_name.contains(blocked.as_str())
                {
                    findings.push(ScanFinding {
                        severity: "critical".to_string(),
                        category: "reputation".to_string(),
                        module: "server-reputation".to_string(),
                        description: format!(
                            "Server '{}' in {} matches threat intel blocklist entry: {}",
                            server_name, client_name, blocked
                        ),
                        affected_resource: format!("{}:{}", client_name, server_name),
                        fix_suggestion: format!(
                            "Remove '{}' immediately - it is flagged in the threat intelligence feed",
                            blocked
                        ),
                        fix_action: None,
                        ai_analysis: None,
                    });
                }
            }

            // --- Dangerous argument detection ---
            for arg in &args {
                for dangerous in DANGEROUS_ARGS {
                    if *arg == *dangerous {
                        findings.push(ScanFinding {
                            severity: "high".to_string(),
                            category: "reputation".to_string(),
                            module: "server-reputation".to_string(),
                            description: format!(
                                "Server '{}' in {} uses dangerous flag '{}'",
                                server_name, client_name, dangerous
                            ),
                            affected_resource: format!("{}:{}", client_name, server_name),
                            fix_suggestion: format!(
                                "Remove the '{}' flag and configure explicit permissions instead",
                                dangerous
                            ),
                            fix_action: None,
                            ai_analysis: None,
                        });
                    }
                }
            }

            // --- Servers running from temp directories ---
            let temp_prefixes = ["/tmp/", "/var/tmp/", "/private/tmp/"];
            if temp_prefixes.iter().any(|p| command.starts_with(p))
                || args.iter().any(|a| temp_prefixes.iter().any(|p| a.starts_with(p)))
            {
                findings.push(ScanFinding {
                    severity: "high".to_string(),
                    category: "reputation".to_string(),
                    module: "server-reputation".to_string(),
                    description: format!(
                        "Server '{}' in {} runs from a temporary directory - possible malicious staging",
                        server_name, client_name
                    ),
                    affected_resource: format!("{}:{}", client_name, server_name),
                    fix_suggestion: "Install MCP servers to a permanent, trusted directory".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }

            // --- Suspiciously long base64-encoded arguments ---
            for arg in &args {
                if arg.len() > 200 && looks_like_base64(arg) {
                    findings.push(ScanFinding {
                        severity: "high".to_string(),
                        category: "reputation".to_string(),
                        module: "server-reputation".to_string(),
                        description: format!(
                            "Server '{}' in {} has a suspiciously long base64-encoded argument ({} chars)",
                            server_name, client_name, arg.len()
                        ),
                        affected_resource: format!("{}:{}", client_name, server_name),
                        fix_suggestion: "Inspect the encoded argument - it may contain obfuscated malicious code".to_string(),
                        fix_action: None,
                        ai_analysis: None,
                    });
                    break; // One finding per server is enough
                }
            }

            // --- Command contains eval/exec/spawn ---
            let cmd_lower = full_command.to_lowercase();
            for fragment in DANGEROUS_CMD_FRAGMENTS {
                if cmd_lower.contains(fragment) {
                    findings.push(ScanFinding {
                        severity: "medium".to_string(),
                        category: "reputation".to_string(),
                        module: "server-reputation".to_string(),
                        description: format!(
                            "Server '{}' in {} command contains code-execution pattern: '{}'",
                            server_name, client_name, fragment
                        ),
                        affected_resource: format!("{}:{}", client_name, server_name),
                        fix_suggestion: "Review the server command for unauthorized code execution".to_string(),
                        fix_action: None,
                        ai_analysis: None,
                    });
                    break; // One finding per server for this category
                }
            }

            // --- Typosquatting: npx with unscoped packages ---
            if command == "npx" && !args.is_empty() {
                let pkg = args[0];
                if !pkg.starts_with('@') && !pkg.starts_with("./") && !pkg.starts_with('/') {
                    // Unscoped npm package - lower confidence
                    findings.push(ScanFinding {
                        severity: "low".to_string(),
                        category: "reputation".to_string(),
                        module: "server-reputation".to_string(),
                        description: format!(
                            "Server '{}' in {} uses unscoped npm package '{}' which has higher typosquatting risk",
                            server_name, client_name, pkg
                        ),
                        affected_resource: format!("{}:{}", client_name, server_name),
                        fix_suggestion: "Prefer scoped packages (@org/package) or local installations for security".to_string(),
                        fix_action: None,
                        ai_analysis: None,
                    });

                    // Check similarity to known popular packages
                    if let Some(similar_to) = find_similar_package(pkg, KNOWN_POPULAR) {
                        findings.push(ScanFinding {
                            severity: "high".to_string(),
                            category: "reputation".to_string(),
                            module: "server-reputation".to_string(),
                            description: format!(
                                "Server '{}' in {} uses package '{}' which is suspiciously similar to popular package '{}' - possible typosquatting",
                                server_name, client_name, pkg, similar_to
                            ),
                            affected_resource: format!("{}:{}", client_name, server_name),
                            fix_suggestion: format!(
                                "Verify you intended to install '{}' and not '{}'",
                                pkg, similar_to
                            ),
                            fix_action: None,
                            ai_analysis: None,
                        });
                    }
                }
            }

            // --- Git URL supply chain risk ---
            let has_git_url = args.iter().any(|a| {
                a.starts_with("git+")
                    || a.starts_with("git://")
                    || a.starts_with("https://github.com/")
                    || a.starts_with("https://gitlab.com/")
                    || a.ends_with(".git")
            });
            if has_git_url {
                findings.push(ScanFinding {
                    severity: "medium".to_string(),
                    category: "reputation".to_string(),
                    module: "server-reputation".to_string(),
                    description: format!(
                        "Server '{}' in {} is installed from a git URL - bypasses npm registry checks",
                        server_name, client_name
                    ),
                    affected_resource: format!("{}:{}", client_name, server_name),
                    fix_suggestion: "Install from a registry with version pinning instead of a git URL".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }

            // --- Local scripts without absolute paths ---
            if command == "node" || command == "python" || command == "python3" {
                if let Some(script) = args.first() {
                    if !script.starts_with('/') && !script.starts_with("./") && !script.starts_with('-') {
                        findings.push(ScanFinding {
                            severity: "low".to_string(),
                            category: "reputation".to_string(),
                            module: "server-reputation".to_string(),
                            description: format!(
                                "Server '{}' in {} uses relative path '{}' - may resolve unexpectedly",
                                server_name, client_name, script
                            ),
                            affected_resource: format!("{}:{}", client_name, server_name),
                            fix_suggestion: "Use absolute paths for server scripts".to_string(),
                            fix_action: None,
                            ai_analysis: None,
                        });
                    }
                }
            }
        }
    }

    // Report blocklist status
    if blocklist_path.exists() {
        if blocklist_entries.is_empty() {
            // We loaded successfully but had zero entries (or file had entries
            // but none with a "name" field). Only warn if the file parses but
            // the entries array is explicitly empty.
            if let Ok(bl_contents) = std::fs::read_to_string(&blocklist_path) {
                if let Ok(blocklist) = serde_json::from_str::<serde_json::Value>(&bl_contents) {
                    if let Some(entries) = blocklist.get("entries").and_then(|v| v.as_array()) {
                        if entries.is_empty() {
                            findings.push(ScanFinding {
                                severity: "low".to_string(),
                                category: "reputation".to_string(),
                                module: "server-reputation".to_string(),
                                description: "Threat blocklist is empty - no known threats to check against".to_string(),
                                affected_resource: blocklist_path.to_string_lossy().to_string(),
                                fix_suggestion: "Update threat intelligence feed from Settings > Threat Intel".to_string(),
                                fix_action: None,
                                ai_analysis: None,
                            });
                        }
                    }
                }
            }
        }
    } else {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "reputation".to_string(),
            module: "server-reputation".to_string(),
            description: "No local threat blocklist found - reputation checks are limited".to_string(),
            affected_resource: blocklist_path.to_string_lossy().to_string(),
            fix_suggestion: "Enable threat intelligence feed to download the latest blocklist".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    let summary = format!(
        "Checked {} server{} - {} issue{} found",
        servers_checked,
        if servers_checked == 1 { "" } else { "s" },
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );

    ScanModuleResult {
        module_id: "server-reputation".to_string(),
        module_name: "Server Reputation Check".to_string(),
        status: "completed".to_string(),
        findings,
        summary,
    }
}

/// Load blocklist package names from the threat intel feed JSON file.
/// Returns an empty vec if the file doesn't exist or can't be parsed.
fn load_blocklist_entries(path: &Path) -> Vec<String> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let value: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    value
        .get("entries")
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    e.get("name")
                        .and_then(|n| n.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Check if a string looks like base64 encoding (alphanumeric, +, /, =).
fn looks_like_base64(s: &str) -> bool {
    if s.len() < 50 {
        return false;
    }
    let valid_b64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    // At least 90% of characters should be valid base64
    valid_b64_chars * 100 / s.len() > 90
}

/// Find if a package name is suspiciously similar to a known popular package.
/// Uses a simple edit-distance heuristic: if the name differs by only 1-2 characters
/// from a popular package but is not identical, flag it.
fn find_similar_package<'a>(name: &str, popular: &[&'a str]) -> Option<&'a str> {
    for &known in popular {
        if name == known {
            continue;
        }
        let dist = simple_edit_distance(name, known);
        // Flag if distance is 1 or 2 (likely typosquat)
        if dist > 0 && dist <= 2 {
            return Some(known);
        }
    }
    None
}

/// Simple Levenshtein edit distance (bounded to keep runtime reasonable).
fn simple_edit_distance(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let a_len = a_bytes.len();
    let b_len = b_bytes.len();

    // Quick reject: if length difference > 2, distance > 2
    if a_len.abs_diff(b_len) > 2 {
        return 3;
    }

    // Use a simple two-row DP for Levenshtein distance
    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

// ---------------------------------------------------------------------------
// Module 4: System Security Posture
// ---------------------------------------------------------------------------

pub fn scan_system_posture(daemon_connected: bool) -> ScanModuleResult {
    let home = home_dir().unwrap_or_default();
    let mut findings = Vec::new();

    // Check daemon running
    if !daemon_connected {
        findings.push(ScanFinding {
            severity: "critical".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "RookBot daemon is not running - no real-time protection active".to_string(),
            affected_resource: "daemon".to_string(),
            fix_suggestion: "Start the daemon from the Dashboard".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    // Check config directory exists
    let config_dir = home.join(".config/rookbot");
    if !config_dir.exists() {
        findings.push(ScanFinding {
            severity: "medium".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "Configuration directory does not exist".to_string(),
            affected_resource: config_dir.to_string_lossy().to_string(),
            fix_suggestion: "Run the setup wizard or start the daemon to create configuration".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    // Check policy file exists
    let policy_path = config_dir.join("policy.toml");
    if !policy_path.exists() {
        findings.push(ScanFinding {
            severity: "high".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "No policy file found - security rules are not configured".to_string(),
            affected_resource: policy_path.to_string_lossy().to_string(),
            fix_suggestion: "Create a policy file or apply a template from the Policy page".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    // Check data directory
    let data_dir = home.join(".local/share/rookbot");
    if !data_dir.exists() {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "Data directory does not exist - audit logs and profiles not being stored".to_string(),
            affected_resource: data_dir.to_string_lossy().to_string(),
            fix_suggestion: "Start the daemon to initialize the data directory".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    // Check audit log exists and has recent entries
    let audit_log = data_dir.join("audit.jsonl");
    if audit_log.exists() {
        if let Ok(metadata) = std::fs::metadata(&audit_log) {
            if let Ok(modified) = metadata.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                if age.as_secs() > 86400 {
                    findings.push(ScanFinding {
                        severity: "medium".to_string(),
                        category: "system".to_string(),
                        module: "system-posture".to_string(),
                        description: format!(
                            "Audit log has not been updated in {} hours",
                            age.as_secs() / 3600
                        ),
                        affected_resource: audit_log.to_string_lossy().to_string(),
                        fix_suggestion: "Ensure the daemon is running and processing events".to_string(),
                        fix_action: None,
                        ai_analysis: None,
                    });
                }
            }
        }
    }

    // Check socket file
    let socket_path = data_dir.join("rookbot.sock");
    if !socket_path.exists() && daemon_connected {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "Socket file not found (daemon may be using alternative IPC)".to_string(),
            affected_resource: socket_path.to_string_lossy().to_string(),
            fix_suggestion: "Check daemon configuration for socket path".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    // Check threat intel feed
    let feed_path = data_dir.join("threat_intel/feed_meta.json");
    if feed_path.exists() {
        if let Ok(meta_contents) = std::fs::read_to_string(&feed_path) {
            if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_contents) {
                if let Some(updated) = meta.get("last_updated").and_then(|v| v.as_str()) {
                    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(updated) {
                        let age = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
                        if age.num_hours() > 48 {
                            findings.push(ScanFinding {
                                severity: "medium".to_string(),
                                category: "system".to_string(),
                                module: "system-posture".to_string(),
                                description: format!(
                                    "Threat intelligence feed is {} hours out of date",
                                    age.num_hours()
                                ),
                                affected_resource: "threat-intel-feed".to_string(),
                                fix_suggestion: "Update the threat feed from Settings > Threat Intel".to_string(),
                                fix_action: None,
                                ai_analysis: None,
                            });
                        }
                    }
                }
            }
        }
    } else {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "Threat intelligence feed has never been downloaded".to_string(),
            affected_resource: "threat-intel-feed".to_string(),
            fix_suggestion: "Enable and update threat intelligence from Settings".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    // Check behavioral profiles exist
    let profiles_dir = data_dir.join("profiles");
    if profiles_dir.exists() {
        let profile_count = std::fs::read_dir(&profiles_dir)
            .map(|entries| entries.filter_map(|e| e.ok()).count())
            .unwrap_or(0);
        if profile_count == 0 {
            findings.push(ScanFinding {
                severity: "low".to_string(),
                category: "system".to_string(),
                module: "system-posture".to_string(),
                description: "No behavioral profiles found - anomaly detection is not active".to_string(),
                affected_resource: profiles_dir.to_string_lossy().to_string(),
                fix_suggestion: "Wrap and use MCP servers to build behavioral baselines".to_string(),
                fix_action: None,
                ai_analysis: None,
            });
        }
    }

    // Check SLM model availability
    let model_paths = [
        data_dir.join("models"),
        home.join(".cache/rookbot/models"),
    ];
    let slm_available = model_paths.iter().any(|p: &PathBuf| {
        p.exists()
            && std::fs::read_dir(p)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .any(|e| {
                            e.path()
                                .extension()
                                .map(|ext| ext == "gguf")
                                .unwrap_or(false)
                        })
                })
                .unwrap_or(false)
    });
    if !slm_available {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "system".to_string(),
            module: "system-posture".to_string(),
            description: "No SLM model found - local AI analysis is not available".to_string(),
            affected_resource: "slm-model".to_string(),
            fix_suggestion: "Download a GGUF model for local security analysis enrichment".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    let summary = if findings.is_empty() {
        "System security posture is strong".to_string()
    } else {
        let critical = findings
            .iter()
            .filter(|f| f.severity == "critical")
            .count();
        if critical > 0 {
            format!(
                "{} issue{} found ({} critical)",
                findings.len(),
                if findings.len() == 1 { "" } else { "s" },
                critical
            )
        } else {
            format!(
                "{} issue{} found",
                findings.len(),
                if findings.len() == 1 { "" } else { "s" }
            )
        }
    };

    ScanModuleResult {
        module_id: "system-posture".to_string(),
        module_name: "System Security Posture".to_string(),
        status: "completed".to_string(),
        findings,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Module 5: Behavioral Anomaly Review
// ---------------------------------------------------------------------------

pub fn scan_behavioral_anomalies() -> ScanModuleResult {
    let home = home_dir().unwrap_or_default();
    let data_dir = home.join(".local/share/rookbot");
    let profiles_dir = data_dir.join("profiles");
    let mut findings = Vec::new();

    if !profiles_dir.exists() {
        return ScanModuleResult {
            module_id: "behavioral-anomaly".to_string(),
            module_name: "Behavioral Anomaly Review".to_string(),
            status: "completed".to_string(),
            findings: vec![ScanFinding {
                severity: "low".to_string(),
                category: "behavioral".to_string(),
                module: "behavioral-anomaly".to_string(),
                description: "No behavioral profiles directory found - skipping anomaly review"
                    .to_string(),
                affected_resource: profiles_dir.to_string_lossy().to_string(),
                fix_suggestion:
                    "Use wrapped MCP servers to build behavioral baselines over time".to_string(),
                fix_action: None,
                ai_analysis: None,
            }],
            summary: "No behavioral data available for analysis".to_string(),
        };
    }

    let profile_files: Vec<_> = std::fs::read_dir(&profiles_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "json")
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();

    if profile_files.is_empty() {
        return ScanModuleResult {
            module_id: "behavioral-anomaly".to_string(),
            module_name: "Behavioral Anomaly Review".to_string(),
            status: "completed".to_string(),
            findings: vec![ScanFinding {
                severity: "low".to_string(),
                category: "behavioral".to_string(),
                module: "behavioral-anomaly".to_string(),
                description: "No behavioral profile files found".to_string(),
                affected_resource: profiles_dir.to_string_lossy().to_string(),
                fix_suggestion:
                    "Use wrapped MCP servers to build behavioral baselines".to_string(),
                fix_action: None,
                ai_analysis: None,
            }],
            summary: "No behavioral profiles to analyze".to_string(),
        };
    }

    let mut profiles_analyzed = 0u32;
    let mut learning_count = 0u32;

    for entry in &profile_files {
        let path = entry.path();
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let profile: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(_) => continue,
        };

        profiles_analyzed += 1;
        let server_name = profile
            .get("server_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let learning = profile
            .get("learning_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        if learning {
            learning_count += 1;
            continue;
        }

        // Check for anomalous patterns in the profile data
        let observation_count = profile
            .get("observation_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Check network profile for unusual patterns
        if let Some(net) = profile.get("network_profile") {
            let has_networked = net
                .get("has_networked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let hosts_count = net
                .get("observed_hosts")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .or_else(|| {
                    net.get("observed_hosts")
                        .and_then(|v| v.as_object())
                        .map(|o| o.len())
                })
                .unwrap_or(0);

            if has_networked && hosts_count > 10 {
                findings.push(ScanFinding {
                    severity: "medium".to_string(),
                    category: "behavioral".to_string(),
                    module: "behavioral-anomaly".to_string(),
                    description: format!(
                        "Server '{}' communicates with {} distinct hosts - unusually high network diversity",
                        server_name, hosts_count
                    ),
                    affected_resource: format!("profile:{}", server_name),
                    fix_suggestion: "Review the server's network connections for unauthorized destinations".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }
        }

        // Check file profile for broad territory
        if let Some(file) = profile.get("file_profile") {
            let prefixes = file
                .get("directory_prefixes")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .or_else(|| {
                    file.get("directory_prefixes")
                        .and_then(|v| v.as_object())
                        .map(|o| o.len())
                })
                .unwrap_or(0);

            if prefixes > 15 {
                findings.push(ScanFinding {
                    severity: "medium".to_string(),
                    category: "behavioral".to_string(),
                    module: "behavioral-anomaly".to_string(),
                    description: format!(
                        "Server '{}' accesses {} different directory trees - unusually broad file territory",
                        server_name, prefixes
                    ),
                    affected_resource: format!("profile:{}", server_name),
                    fix_suggestion: "Consider restricting the server's filesystem access scope".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }

            let write_count = file
                .get("write_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let read_count = file
                .get("read_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if read_count > 0 && write_count > read_count * 2 {
                findings.push(ScanFinding {
                    severity: "medium".to_string(),
                    category: "behavioral".to_string(),
                    module: "behavioral-anomaly".to_string(),
                    description: format!(
                        "Server '{}' has unusual write:read ratio ({} writes vs {} reads)",
                        server_name, write_count, read_count
                    ),
                    affected_resource: format!("profile:{}", server_name),
                    fix_suggestion: "Investigate if the high write rate is expected behavior".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }
        }

        // Check tool profile for unusual tool count
        if let Some(tools) = profile.get("tool_profile") {
            let tool_count = tools
                .get("tool_counts")
                .and_then(|v| v.as_object())
                .map(|o| o.len())
                .unwrap_or(0);

            if tool_count > 20 && observation_count < 500 {
                findings.push(ScanFinding {
                    severity: "low".to_string(),
                    category: "behavioral".to_string(),
                    module: "behavioral-anomaly".to_string(),
                    description: format!(
                        "Server '{}' uses {} distinct tools with only {} observations - many tools are undersampled",
                        server_name, tool_count, observation_count
                    ),
                    affected_resource: format!("profile:{}", server_name),
                    fix_suggestion: "Allow more observations to build a reliable baseline".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }
        }

        // Check temporal profile for very rapid bursts
        if let Some(temporal) = profile.get("temporal_profile") {
            let burst_mean = temporal
                .get("burst_size_mean")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            if burst_mean > 20.0 {
                findings.push(ScanFinding {
                    severity: "medium".to_string(),
                    category: "behavioral".to_string(),
                    module: "behavioral-anomaly".to_string(),
                    description: format!(
                        "Server '{}' has high average burst size ({:.1} events) - could indicate automated exfiltration",
                        server_name, burst_mean
                    ),
                    affected_resource: format!("profile:{}", server_name),
                    fix_suggestion: "Review recent activity for suspicious rapid-fire operations".to_string(),
                    fix_action: None,
                    ai_analysis: None,
                });
            }
        }
    }

    if learning_count > 0 {
        findings.push(ScanFinding {
            severity: "low".to_string(),
            category: "behavioral".to_string(),
            module: "behavioral-anomaly".to_string(),
            description: format!(
                "{} server(s) still in learning mode - anomaly detection not yet active for them",
                learning_count
            ),
            affected_resource: "behavioral-engine".to_string(),
            fix_suggestion: "Continue using these servers to complete the learning phase".to_string(),
            fix_action: None,
            ai_analysis: None,
        });
    }

    let summary = format!(
        "Analyzed {} profile{} ({} learning) - {} issue{} found",
        profiles_analyzed,
        if profiles_analyzed == 1 { "" } else { "s" },
        learning_count,
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );

    ScanModuleResult {
        module_id: "behavioral-anomaly".to_string(),
        module_name: "Behavioral Anomaly Review".to_string(),
        status: "completed".to_string(),
        findings,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Shared helper: convert clawdefender_scanner Finding → ScanFinding
// ---------------------------------------------------------------------------

fn finding_to_scan_finding(
    f: &clawdefender_scanner::finding::Finding,
    module_id: &str,
) -> ScanFinding {
    let severity = match f.severity {
        clawdefender_scanner::finding::Severity::Critical => "critical",
        clawdefender_scanner::finding::Severity::High => "high",
        clawdefender_scanner::finding::Severity::Medium => "medium",
        clawdefender_scanner::finding::Severity::Low => "low",
        clawdefender_scanner::finding::Severity::Info => "info",
    };

    let category = f.category.to_string().to_lowercase().replace(' ', "-");

    ScanFinding {
        severity: severity.to_string(),
        category,
        module: module_id.to_string(),
        description: format!("{}: {}", f.title, f.description),
        affected_resource: f
            .evidence
            .files_modified
            .first()
            .cloned()
            .unwrap_or_else(|| f.id.clone()),
        fix_suggestion: f.remediation.clone(),
        fix_action: None,
        ai_analysis: None,
    }
}

fn make_module_result(
    module_id: &str,
    module_name: &str,
    findings: Vec<ScanFinding>,
    empty_msg: &str,
) -> ScanModuleResult {
    let summary = if findings.is_empty() {
        empty_msg.to_string()
    } else {
        format!("{} issue(s) found", findings.len())
    };
    ScanModuleResult {
        module_id: module_id.to_string(),
        module_name: module_name.to_string(),
        status: "completed".to_string(),
        findings,
        summary,
    }
}

fn module_error_result(module_id: &str, module_name: &str, err: anyhow::Error) -> ScanModuleResult {
    ScanModuleResult {
        module_id: module_id.to_string(),
        module_name: module_name.to_string(),
        status: "completed".to_string(),
        findings: vec![],
        summary: format!("Skipped: {}", err),
    }
}

// ---------------------------------------------------------------------------
// Module 6: TCC Permission Audit
// ---------------------------------------------------------------------------

pub async fn scan_tcc_permissions() -> ScanModuleResult {
    use clawdefender_scanner::modules::tcc_audit::TccAuditModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = TccAuditModule::new();
    match module.run_standalone().await {
        Ok(findings) => {
            let sf: Vec<ScanFinding> = findings
                .iter()
                .map(|f| finding_to_scan_finding(f, "tcc-audit"))
                .collect();
            make_module_result("tcc-audit", "TCC Permission Audit", sf, "No TCC permission issues found")
        }
        Err(e) => module_error_result("tcc-audit", "TCC Permission Audit", e),
    }
}

// ---------------------------------------------------------------------------
// Module 7: File Integrity Monitor
// ---------------------------------------------------------------------------

pub async fn scan_file_integrity() -> ScanModuleResult {
    use clawdefender_scanner::modules::file_integrity::FileIntegrityModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = FileIntegrityModule::new();
    match module.run_standalone().await {
        Ok(findings) => {
            let sf: Vec<ScanFinding> = findings
                .iter()
                .map(|f| finding_to_scan_finding(f, "file-integrity"))
                .collect();
            make_module_result(
                "file-integrity",
                "File Integrity Monitor",
                sf,
                "No file integrity violations found",
            )
        }
        Err(e) => module_error_result("file-integrity", "File Integrity Monitor", e),
    }
}

// ---------------------------------------------------------------------------
// Module 8: Clipboard Security Check
// ---------------------------------------------------------------------------

pub async fn scan_clipboard() -> ScanModuleResult {
    use clawdefender_scanner::modules::clipboard_monitor::ClipboardMonitorModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = ClipboardMonitorModule::new();
    match module.run_standalone().await {
        Ok(findings) => {
            let sf: Vec<ScanFinding> = findings
                .iter()
                .map(|f| finding_to_scan_finding(f, "clipboard-check"))
                .collect();
            make_module_result(
                "clipboard-check",
                "Clipboard Security Check",
                sf,
                "Clipboard content is safe",
            )
        }
        Err(e) => module_error_result("clipboard-check", "Clipboard Security Check", e),
    }
}

// ---------------------------------------------------------------------------
// Module 9: Process Memory Scan
// ---------------------------------------------------------------------------

pub async fn scan_process_memory() -> ScanModuleResult {
    use clawdefender_scanner::modules::memory_scanner::MemoryScanModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = MemoryScanModule::new();
    match module.run_standalone().await {
        Ok(findings) => {
            let sf: Vec<ScanFinding> = findings
                .iter()
                .map(|f| finding_to_scan_finding(f, "memory-scan"))
                .collect();
            make_module_result(
                "memory-scan",
                "Process Memory Scan",
                sf,
                "No suspicious process memory patterns found",
            )
        }
        Err(e) => module_error_result("memory-scan", "Process Memory Scan", e),
    }
}

// ---------------------------------------------------------------------------
// Module 10: CIS Benchmark Compliance
// ---------------------------------------------------------------------------

pub async fn scan_cis_benchmark() -> ScanModuleResult {
    use clawdefender_scanner::modules::cis_benchmark::CisBenchmarkModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = CisBenchmarkModule::new();
    match module.run_standalone().await {
        Ok(findings) => {
            let sf: Vec<ScanFinding> = findings
                .iter()
                .map(|f| finding_to_scan_finding(f, "cis-benchmark"))
                .collect();
            make_module_result(
                "cis-benchmark",
                "CIS Benchmark Compliance",
                sf,
                "All CIS benchmark checks passed",
            )
        }
        Err(e) => module_error_result("cis-benchmark", "CIS Benchmark Compliance", e),
    }
}

// ---------------------------------------------------------------------------
// Module 11: Browser Extension Audit
// ---------------------------------------------------------------------------

pub async fn scan_browser_extensions() -> ScanModuleResult {
    use clawdefender_scanner::modules::browser_audit::BrowserAuditModule;
    use clawdefender_scanner::modules::ScanModule;

    let module = BrowserAuditModule::new();
    match module.run_standalone().await {
        Ok(findings) => {
            let sf: Vec<ScanFinding> = findings
                .iter()
                .map(|f| finding_to_scan_finding(f, "browser-audit"))
                .collect();
            make_module_result(
                "browser-audit",
                "Browser Extension Audit",
                sf,
                "No browser extension issues found",
            )
        }
        Err(e) => module_error_result("browser-audit", "Browser Extension Audit", e),
    }
}
