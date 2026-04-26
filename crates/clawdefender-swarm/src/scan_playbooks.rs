//! Scan playbooks that guide Claude's security investigations.
//!
//! Each playbook defines a structured, multi-stage investigation plan with
//! a tailored system prompt, estimated resource usage, and the set of tools
//! Claude should lean on at each stage.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A complete scan playbook that drives a Claude security investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanPlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stages: Vec<PlaybookStage>,
    pub system_prompt: String,
    pub estimated_tool_calls: u32,
    pub estimated_duration_secs: u64,
    pub estimated_tokens: u64,
}

/// A single stage within a playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStage {
    pub name: String,
    pub description: String,
    pub key_tools: Vec<String>,
}

/// Lightweight summary of a playbook for listing in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookSummary {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stage_count: usize,
    pub estimated_duration_secs: u64,
    pub estimated_cost_usd: f64,
}

// ---------------------------------------------------------------------------
// Shared prompt fragments
// ---------------------------------------------------------------------------

/// Instructions common to every playbook — finding/remediation tags, stage
/// signalling, and output discipline.
const COMMON_INSTRUCTIONS: &str = r#"
## Severity Classification — MANDATORY for every finding

CRITICAL: Active exploitation or imminent data loss.
  Examples: credentials being exfiltrated right now, active kill chain stage 4+,
  malware executing, unauthorized remote access active.

HIGH: Serious vulnerability that could lead to compromise with minimal effort.
  Examples: no security policy at all (zero rules = zero protection),
  credentials exposed in plain text in config files, unauthorized LaunchAgents
  that modify system behavior, MCP servers with shell execution running unwrapped.

MEDIUM: Significant weakness that requires some conditions to exploit.
  Examples: overly permissive policy rules (allow-all wildcards), servers with
  unnecessary network access, behavioral drift detected, weak default settings.

LOW: Minor issue or hardening recommendation.
  Examples: disabled but present policy rules, non-sensitive config files with
  loose permissions, optional security features not enabled.

INFO: Informational observation, no security impact.
  Examples: system configuration details, normal operational status, feature
  availability notes.

IMPORTANT: Err toward higher severity, not lower. An empty security policy is
HIGH, not INFO. Unauthorized LaunchAgents killing applications is HIGH, not INFO.
When in doubt, go one level higher — the user can always dismiss, but a missed
critical finding is dangerous.

## Output Format

When you discover a security issue, emit a structured finding block:

```
[FINDING severity=HIGH]
Title: <specific, descriptive title — not generic>
Description: <what you found, WHY it matters, and the security IMPACT>
Evidence: <tool_call_id or quoted output that supports the finding>
Remediation: <SPECIFIC action — exact command or rule, not "review and fix">
[/FINDING]
```

The severity MUST reflect the actual risk:
- Empty policy = HIGH. Unauthorized processes killing apps = HIGH.
- Missing optional feature = LOW. System configuration note = INFO.

BAD title: "Security Issue Found"
GOOD title: "Four Unauthorized LaunchAgents Auto-Terminate User Applications"

BAD description: "LaunchAgents are configured to run."
GOOD description: "Four LaunchAgents (brave-killer, firefox-killer, music-killer,
safari-killer) terminate browsers on login via launchd. This prevents normal use
and could mask malicious activity by eliminating browsers that might detect it."

BAD remediation: "Review and remove if unauthorized."
GOOD remediation: "Run: launchctl bootout gui/501 ~/Library/LaunchAgents/com.user.brave-killer.plist && rm ~/Library/LaunchAgents/com.user.brave-killer.plist"

When you have a concrete fix, emit a remediation block:

```
[REMEDIATION for=FINDING-<N> risk=low reversible=yes]
Type: <policy_change | system_command | config_edit | manual>
Action: <human-readable description of the fix>
Rule: <exact rule definition, for policy_change>
Command: <exact command to run, for system_command>
Sudo: <yes|no, for system_command>
File: <path, for config_edit>
Current: <current value, for config_edit>
Proposed: <proposed value, for config_edit>
Diff: <diff preview, for config_edit>
Instructions: <step-by-step, for manual>
[/REMEDIATION]
```

## Deduplication

Before reporting a finding, check if you already reported the same or a very
similar issue in a previous stage. If you did, do NOT report it again — each
unique issue should appear ONLY ONCE in your results.

## Investigation Depth

When you discover something suspicious, do NOT just report it — dig deeper:

For suspicious LaunchAgents/processes:
- Read the plist file (run_scan_command with plutil -p) to see what command it runs
- Check if it's currently active (launchctl list)
- Check when it was created (stat)
- Assess what damage it could cause

For policy gaps:
- Quantify the gap: how many servers are unprotected?
- Identify the highest-risk unprotected server
- Propose specific rules, not generic advice

For system issues:
- Check the actual current state (run the verification command)
- Provide the exact command to fix it

Spend 2-3 tool calls per significant finding to gather evidence. A scan that
discovers an issue but doesn't investigate it is incomplete.

## Stage Protocol

- After completing each stage, output: STAGE COMPLETE: <stage_name>
- If a stage found no issues, still report completion with what was checked.
- When ALL stages are done, output: SCAN COMPLETE
- Do NOT silently skip stages. Every stage produces output.

## General Rules

- Be thorough but concise.
- Prefer tools over assumptions — always verify before reporting.
- Never fabricate evidence. If a tool returns no data, say so.
- Never read or display actual credential values (passwords, tokens, private keys).
  Only report *that* credentials are exposed, not *what* they contain.
- Number your findings sequentially: FINDING-1, FINDING-2, etc.
- For every finding, explain the security IMPACT — connect it to a real-world risk.
"#;

// ---------------------------------------------------------------------------
// Playbook constructors
// ---------------------------------------------------------------------------

fn mcp_security_audit() -> ScanPlaybook {
    ScanPlaybook {
        id: "mcp_security_audit".into(),
        name: "MCP Security Audit".into(),
        description: "Comprehensive audit of all MCP servers — inventory, configuration, \
            behavior, reputation, and policy coverage."
            .into(),
        stages: vec![
            PlaybookStage {
                name: "Server Inventory".into(),
                description: "Identify all MCP servers, check wrapped status, and review \
                    trust levels."
                    .into(),
                key_tools: vec![
                    "get_system_posture".into(),
                    "query_events".into(),
                ],
            },
            PlaybookStage {
                name: "Configuration Analysis".into(),
                description: "Read each MCP client config file. Check for hardcoded \
                    credentials, insecure transport, and overprivileged configurations."
                    .into(),
                key_tools: vec!["read_file".into(), "list_directory".into()],
            },
            PlaybookStage {
                name: "Behavioral Review".into(),
                description: "Pull the behavioral profile for each server. Compare actual \
                    tool usage and file access against declared capabilities."
                    .into(),
                key_tools: vec![
                    "get_server_profile".into(),
                    "query_events".into(),
                ],
            },
            PlaybookStage {
                name: "Threat Intelligence".into(),
                description: "Cross-reference each server against blocklists and IoC \
                    databases."
                    .into(),
                key_tools: vec!["check_reputation".into()],
            },
            PlaybookStage {
                name: "Policy Gap Analysis".into(),
                description: "Retrieve the current policy and identify uncovered servers, \
                    overly broad rules, and missing restrictions."
                    .into(),
                key_tools: vec!["get_policy".into()],
            },
        ],
        system_prompt: format!(
            r#"You are RookBot's security agent performing an MCP Security Audit.

Your mission: systematically audit every MCP server on this machine for security risks.

## Investigation Plan

### Stage 1 — Server Inventory
Use get_system_posture() and query_events(time_range="last_24h") to build a complete
list of MCP servers. For each server note: name, wrapped/unwrapped, trust level, and
recent event volume.

### Stage 2 — Configuration Analysis
Use read_file() to inspect MCP client configuration files (e.g.
~/Library/Application Support/Claude/claude_desktop_config.json). Look for:
- Hardcoded API keys, tokens, or passwords
- Insecure transport (http:// instead of https://)
- Overprivileged tool grants
- Missing security headers or sandboxing

### Stage 3 — Behavioral Review
Use get_server_profile() for every server discovered in Stage 1. Compare actual
behavior against declared capabilities:
- Tools called that weren't declared
- File access outside expected directories
- Unexpected network connections
- Anomaly score trends

### Stage 4 — Threat Intelligence
Use check_reputation() for each server name and any external domains/IPs found in
Stage 3. Flag any blocklist or IoC matches.

### Stage 5 — Policy Gap Analysis
Use get_policy() to retrieve the current ruleset. Identify:
- Servers with no policy rules at all
- Overly broad "allow all" rules
- Missing rate limits for high-activity servers
- No network restrictions for servers making outbound connections

{common}
"#,
            common = COMMON_INSTRUCTIONS,
        ),
        estimated_tool_calls: 30,
        estimated_duration_secs: 300,
        estimated_tokens: 50_000,
    }
}

fn system_hardening() -> ScanPlaybook {
    ScanPlaybook {
        id: "system_hardening".into(),
        name: "System Hardening Check".into(),
        description: "Audit macOS security settings — SIP, Gatekeeper, FileVault, firewall, \
            SSH, LaunchAgents, and file permissions."
            .into(),
        stages: vec![
            PlaybookStage {
                name: "macOS Security Settings".into(),
                description: "Check SIP, Gatekeeper, FileVault, and firewall status using \
                    system inspection commands."
                    .into(),
                key_tools: vec![
                    "get_system_posture".into(),
                    "run_command".into(),
                ],
            },
            PlaybookStage {
                name: "SSH Configuration".into(),
                description: "Review SSH client and server configuration for insecure \
                    settings."
                    .into(),
                key_tools: vec!["read_file".into()],
            },
            PlaybookStage {
                name: "Login Items and LaunchAgents".into(),
                description: "List LaunchAgents and LaunchDaemons. Identify unauthorized \
                    or suspicious persistence mechanisms."
                    .into(),
                key_tools: vec![
                    "list_directory".into(),
                    "read_file".into(),
                    "run_command".into(),
                ],
            },
            PlaybookStage {
                name: "File Permissions".into(),
                description: "Check permissions on sensitive directories and files, \
                    including SSH keys and config directories."
                    .into(),
                key_tools: vec!["list_directory".into(), "run_command".into()],
            },
            PlaybookStage {
                name: "Network Configuration".into(),
                description: "Review network services, DNS settings, and firewall rules."
                    .into(),
                key_tools: vec!["run_command".into()],
            },
        ],
        system_prompt: format!(
            r#"You are RookBot's security agent performing a System Hardening Check.

Your mission: audit the macOS security posture and identify hardening gaps.

## Investigation Plan

### Stage 1 — macOS Security Settings
Use get_system_posture() for an overview, then run_command() with:
- "csrutil status" — System Integrity Protection
- "spctl --status" — Gatekeeper
- "fdesetup status" — FileVault disk encryption
- "pfctl -s info" — Packet filter firewall
Flag anything that is disabled or misconfigured.

### Stage 2 — SSH Configuration
Use read_file() on ~/.ssh/config and /etc/ssh/sshd_config (if accessible).
Look for:
- PermitRootLogin enabled
- PasswordAuthentication enabled when key-based is available
- Weak cipher suites or key exchange algorithms
- Missing StrictHostKeyChecking

### Stage 3 — Login Items and LaunchAgents
Use list_directory() on ~/Library/LaunchAgents and run_command("launchctl list | grep -i clawdefender").
Identify any:
- Unexpected or unsigned LaunchAgents
- LaunchDaemons running as root
- Persistence mechanisms from MCP servers

### Stage 4 — File Permissions
Check file permissions on security-sensitive paths:
- ~/.ssh/ (keys should be 600, directory 700)
- ~/.config/rookbot/
- Any config files found to contain credentials

### Stage 5 — Network Configuration
Use run_command("networksetup -listallnetworkservices") to enumerate interfaces.
Review for:
- Unnecessary network services enabled
- DNS pointing to untrusted resolvers
- Missing firewall rules

{common}
"#,
            common = COMMON_INSTRUCTIONS,
        ),
        estimated_tool_calls: 25,
        estimated_duration_secs: 240,
        estimated_tokens: 40_000,
    }
}

fn credential_exposure() -> ScanPlaybook {
    ScanPlaybook {
        id: "credential_exposure".into(),
        name: "Credential Exposure Scan".into(),
        description: "Scan for exposed credentials in MCP configs, shell history, \
            environment variables, and .env files. Never reads actual secret values."
            .into(),
        stages: vec![
            PlaybookStage {
                name: "MCP Server Config Secrets".into(),
                description: "Scan MCP server configuration files for embedded API keys, \
                    tokens, and passwords."
                    .into(),
                key_tools: vec!["read_file".into()],
            },
            PlaybookStage {
                name: "Shell History".into(),
                description: "Check shell history files for accidentally leaked credentials \
                    in command arguments."
                    .into(),
                key_tools: vec!["read_file".into()],
            },
            PlaybookStage {
                name: "Environment Variables".into(),
                description: "Check for sensitive environment variables that may be visible \
                    to MCP servers."
                    .into(),
                key_tools: vec!["run_command".into(), "query_events".into()],
            },
            PlaybookStage {
                name: "Sensitive File Access".into(),
                description: "Review recent file access events for reads of credential \
                    files, .env files, and key material."
                    .into(),
                key_tools: vec!["query_events".into(), "search_events".into()],
            },
            PlaybookStage {
                name: "Dotenv Files".into(),
                description: "Check for .env files in common locations that may contain \
                    unprotected secrets."
                    .into(),
                key_tools: vec![
                    "list_directory".into(),
                    "search_events".into(),
                ],
            },
        ],
        system_prompt: format!(
            r#"You are RookBot's security agent performing a Credential Exposure Scan.

Your mission: find exposed credentials without ever reading or displaying their values.

CRITICAL SAFETY RULE: You must NEVER read, display, log, or output actual credential
values (passwords, API keys, tokens, private keys). You may only report THAT a
credential is exposed, WHERE it is exposed, and HOW to remediate the exposure.

## Investigation Plan

### Stage 1 — MCP Server Config Secrets
Use read_file() on MCP configuration files. Scan for patterns like:
- "api_key", "token", "password", "secret" in config JSON
- Hardcoded strings that look like credentials (long alphanumeric values)
- Base64-encoded blobs in config values
Report file path and key name only — never the value.

### Stage 2 — Shell History
Use read_file() on ~/.zshrc and ~/.bashrc (which are in the allowlist).
Look for:
- export commands setting secret environment variables
- curl/wget commands with embedded tokens in URLs
- Commands referencing credential files
Report the line pattern, not the actual secret.

### Stage 3 — Environment Variables
Use query_events(time_range="last_24h") and search_events(query="env") to find
MCP servers that accessed environment variables. Check if any server read
variables like API_KEY, SECRET, TOKEN, PASSWORD, AWS_SECRET_ACCESS_KEY, etc.

### Stage 4 — Sensitive File Access
Use query_events(time_range="last_24h") and search_events(query=".ssh") to find
any MCP server that accessed:
- SSH private keys (~/.ssh/id_*)
- AWS credentials (~/.aws/credentials)
- Cloud provider configs
- Keychain files

### Stage 5 — Dotenv Files
Use search_events(query=".env") to find any access to .env files.
Use list_directory() on allowed paths to check for .env files in config directories.

{common}
"#,
            common = COMMON_INSTRUCTIONS,
        ),
        estimated_tool_calls: 20,
        estimated_duration_secs: 180,
        estimated_tokens: 35_000,
    }
}

fn network_security() -> ScanPlaybook {
    ScanPlaybook {
        id: "network_security".into(),
        name: "Network Security Scan".into(),
        description: "Analyze outbound connections from MCP servers, detect data \
            exfiltration patterns, suspicious DNS queries, and untrusted destinations."
            .into(),
        stages: vec![
            PlaybookStage {
                name: "Outbound Connection Inventory".into(),
                description: "Map all outbound connections made by MCP servers — \
                    destinations, ports, and frequency."
                    .into(),
                key_tools: vec![
                    "get_server_profile".into(),
                    "query_events".into(),
                ],
            },
            PlaybookStage {
                name: "Data Exfiltration Patterns".into(),
                description: "Look for signs of data exfiltration — large uploads, \
                    unusual POST requests, encoded payloads."
                    .into(),
                key_tools: vec![
                    "search_events".into(),
                    "query_events".into(),
                ],
            },
            PlaybookStage {
                name: "DNS Analysis".into(),
                description: "Review DNS queries for tunneling, DGA domains, or \
                    resolution of known-bad hostnames."
                    .into(),
                key_tools: vec!["search_events".into()],
            },
            PlaybookStage {
                name: "Suspicious Destinations".into(),
                description: "Cross-reference all contacted IPs and domains against \
                    threat intelligence."
                    .into(),
                key_tools: vec!["check_reputation".into()],
            },
            PlaybookStage {
                name: "Network Policy Coverage".into(),
                description: "Check whether current policies adequately restrict network \
                    activity for each server."
                    .into(),
                key_tools: vec!["get_policy".into()],
            },
        ],
        system_prompt: format!(
            r#"You are RookBot's security agent performing a Network Security Scan.

Your mission: analyze all network activity by MCP servers and identify threats.

## Investigation Plan

### Stage 1 — Outbound Connection Inventory
Use get_server_profile() for each known server to map its network patterns.
Use query_events(time_range="last_24h") filtered by server to find all outbound
connections. Build a table of: server, destination, port, protocol, frequency.

### Stage 2 — Data Exfiltration Patterns
Use search_events(query="POST") and search_events(query="upload") to find potential
data exfiltration. Look for:
- Large payload sizes (> 1MB)
- Connections to non-standard ports
- Base64-encoded data in request bodies
- Connections shortly after reading sensitive files

### Stage 3 — DNS Analysis
Use search_events(query="dns") to review DNS activity. Look for:
- Unusually long subdomains (potential DNS tunneling)
- Domains matching DGA patterns (random-looking strings)
- Resolution of IP addresses in threat intel feeds
- High-frequency DNS queries to the same domain

### Stage 4 — Suspicious Destinations
For every unique IP and domain found in Stages 1-3, use check_reputation()
to verify against blocklists and IoC databases. Flag any matches.

### Stage 5 — Network Policy Coverage
Use get_policy() and cross-reference with the network activity map from Stage 1.
Identify:
- Servers making network connections with no network policy rules
- Servers contacting destinations not in any allowlist
- Missing egress restrictions

{common}
"#,
            common = COMMON_INSTRUCTIONS,
        ),
        estimated_tool_calls: 35,
        estimated_duration_secs: 300,
        estimated_tokens: 45_000,
    }
}

fn behavioral_deep_dive() -> ScanPlaybook {
    ScanPlaybook {
        id: "behavioral_deep_dive".into(),
        name: "Behavioral Deep Dive".into(),
        description: "Deep analysis of MCP server behavior — anomaly trends, privilege \
            escalation patterns, kill chain progression, and learning period comparison."
            .into(),
        stages: vec![
            PlaybookStage {
                name: "Anomaly Ranking".into(),
                description: "Identify the servers with the highest anomaly scores and \
                    most suspicious recent activity."
                    .into(),
                key_tools: vec![
                    "get_server_profile".into(),
                    "query_events".into(),
                ],
            },
            PlaybookStage {
                name: "Behavior Change Timeline".into(),
                description: "Track how each high-anomaly server's behavior has changed \
                    over time."
                    .into(),
                key_tools: vec![
                    "get_server_profile".into(),
                    "query_events".into(),
                    "search_events".into(),
                ],
            },
            PlaybookStage {
                name: "Privilege Escalation Detection".into(),
                description: "Look for gradual privilege escalation — servers requesting \
                    broader permissions or accessing increasingly sensitive resources."
                    .into(),
                key_tools: vec![
                    "query_events".into(),
                    "search_events".into(),
                ],
            },
            PlaybookStage {
                name: "Kill Chain Analysis".into(),
                description: "Check for multi-stage attack patterns matching known kill \
                    chain frameworks."
                    .into(),
                key_tools: vec![
                    "query_events".into(),
                    "get_server_profile".into(),
                ],
            },
            PlaybookStage {
                name: "Learning Period Comparison".into(),
                description: "Compare current behavior to the initial learning period \
                    baseline for each server."
                    .into(),
                key_tools: vec!["get_server_profile".into()],
            },
        ],
        system_prompt: format!(
            r#"You are RookBot's security agent performing a Behavioral Deep Dive.

Your mission: deeply analyze MCP server behavior to detect advanced threats that
surface-level scans may miss.

## Investigation Plan

### Stage 1 — Anomaly Ranking
Use get_server_profile() for every known server. Rank them by anomaly score.
Focus the rest of the investigation on the top offenders (anomaly score >= 0.4).
Use query_events(time_range="last_24h", severity="medium") to see recent flags.

### Stage 2 — Behavior Change Timeline
For each high-anomaly server, use query_events() with different time ranges
(last_hour, last_24h) to build a timeline. Look for:
- Sudden spikes in activity
- New tool usage that wasn't present before
- Changes in file access patterns
- New network destinations

### Stage 3 — Privilege Escalation Detection
Use search_events(query="permission") and search_events(query="access denied")
to find privilege boundary probing. Patterns to flag:
- Repeated access-denied events followed by successful access
- Gradual expansion of file access scope
- Requests for admin-level operations
- Attempts to read security configurations

### Stage 4 — Kill Chain Analysis
Use query_events(time_range="last_24h", severity="high") and cross-reference with
get_server_profile() anomaly history. Map findings to kill chain stages:
1. Reconnaissance — scanning configs, enumerating files
2. Weaponization — downloading tools, preparing payloads
3. Delivery — sending data to external endpoints
4. Exploitation — leveraging access to sensitive resources
5. Installation — creating persistence mechanisms
6. Command & Control — regular check-ins to external servers
7. Actions on Objectives — data theft, credential harvesting

### Stage 5 — Learning Period Comparison
Use get_server_profile() to compare current behavior patterns against the baseline
established during the initial learning period. Flag any significant deviations:
- New tools being called
- New file access patterns
- New network connections
- Changed frequency patterns

{common}
"#,
            common = COMMON_INSTRUCTIONS,
        ),
        estimated_tool_calls: 40,
        estimated_duration_secs: 360,
        estimated_tokens: 55_000,
    }
}

fn full_audit() -> ScanPlaybook {
    // Collect stages from all five individual playbooks.
    let sub_playbooks = [
        mcp_security_audit(),
        system_hardening(),
        credential_exposure(),
        network_security(),
        behavioral_deep_dive(),
    ];

    let mut all_stages: Vec<PlaybookStage> = Vec::new();
    for pb in &sub_playbooks {
        all_stages.push(PlaybookStage {
            name: format!("{} — {}", pb.name, pb.stages[0].name),
            description: format!(
                "Begin the {} sub-audit. Stages: {}",
                pb.name,
                pb.stages
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            key_tools: pb
                .stages
                .iter()
                .flat_map(|s| s.key_tools.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect(),
        });
    }

    ScanPlaybook {
        id: "full_audit".into(),
        name: "Full Security Audit".into(),
        description: "Comprehensive audit combining all five scan playbooks — MCP audit, \
            system hardening, credential exposure, network security, and behavioral \
            deep dive."
            .into(),
        stages: all_stages,
        system_prompt: format!(
            r#"You are RookBot's security agent performing a Full Security Audit.

This is a comprehensive investigation that covers all five scan domains. Work through
each sub-audit methodically, completing all stages before moving to the next.

## Sub-Audits (execute in order)

### 1. MCP Security Audit
- Server Inventory: get_system_posture(), query_events()
- Configuration Analysis: read_file() on MCP configs
- Behavioral Review: get_server_profile() for each server
- Threat Intelligence: check_reputation() for each server
- Policy Gap Analysis: get_policy()

### 2. System Hardening Check
- macOS Security Settings: run_command() for csrutil, spctl, fdesetup, pfctl
- SSH Configuration: read_file() on SSH configs
- Login Items & LaunchAgents: list_directory(), run_command("launchctl list | grep -i clawdefender")
- File Permissions: check sensitive directories
- Network Configuration: run_command("networksetup -listallnetworkservices")

### 3. Credential Exposure Scan
- MCP Server Config Secrets: read_file() for embedded credentials (report presence only)
- Shell History: read_file() on shell configs for leaked secrets
- Environment Variables: query_events(), search_events()
- Sensitive File Access: search_events() for SSH key / credential file access
- Dotenv Files: search_events() for .env access

### 4. Network Security Scan
- Outbound Connections: get_server_profile(), query_events()
- Exfiltration Patterns: search_events() for large transfers
- DNS Analysis: search_events() for DNS anomalies
- Suspicious Destinations: check_reputation()
- Network Policy: get_policy() cross-referenced with connections

### 5. Behavioral Deep Dive
- Anomaly Ranking: get_server_profile() for all servers
- Behavior Timeline: query_events() across time ranges
- Privilege Escalation: search_events() for escalation patterns
- Kill Chain Analysis: map to kill chain stages
- Learning Period Comparison: baseline vs. current behavior

At the end, produce an Executive Summary with:
- Total findings by severity
- Top 3 most critical issues
- Overall security posture rating (A-F)
- Prioritized remediation roadmap

{common}
"#,
            common = COMMON_INSTRUCTIONS,
        ),
        estimated_tool_calls: 200,
        estimated_duration_secs: 1200,
        estimated_tokens: 200_000,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return all available scan playbooks.
pub fn get_all_playbooks() -> Vec<ScanPlaybook> {
    vec![
        mcp_security_audit(),
        system_hardening(),
        credential_exposure(),
        network_security(),
        behavioral_deep_dive(),
        full_audit(),
    ]
}

/// Look up a single playbook by ID.
pub fn get_playbook(id: &str) -> Option<ScanPlaybook> {
    get_all_playbooks().into_iter().find(|p| p.id == id)
}

/// Return lightweight summaries of every playbook.
pub fn get_playbook_summaries() -> Vec<PlaybookSummary> {
    get_all_playbooks()
        .into_iter()
        .map(|p| {
            // Rough cost estimate: $3/MTok input + $15/MTok output.
            // Assume 60% input, 40% output.
            let input_tokens = (p.estimated_tokens as f64) * 0.6;
            let output_tokens = (p.estimated_tokens as f64) * 0.4;
            let cost = (input_tokens / 1_000_000.0) * 3.0
                + (output_tokens / 1_000_000.0) * 15.0;

            PlaybookSummary {
                id: p.id,
                name: p.name,
                description: p.description,
                stage_count: p.stages.len(),
                estimated_duration_secs: p.estimated_duration_secs,
                estimated_cost_usd: (cost * 1000.0).round() / 1000.0,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_six_playbooks_load() {
        let playbooks = get_all_playbooks();
        assert_eq!(playbooks.len(), 6, "expected 6 playbooks");
    }

    #[test]
    fn test_each_playbook_has_stages_and_prompt() {
        for pb in get_all_playbooks() {
            assert!(
                !pb.stages.is_empty(),
                "playbook '{}' must have at least one stage",
                pb.id,
            );
            assert!(
                !pb.system_prompt.is_empty(),
                "playbook '{}' must have a non-empty system prompt",
                pb.id,
            );
            assert!(
                pb.system_prompt.contains("[FINDING"),
                "playbook '{}' system prompt must include FINDING tag instructions",
                pb.id,
            );
            assert!(
                pb.system_prompt.contains("[REMEDIATION"),
                "playbook '{}' system prompt must include REMEDIATION tag instructions",
                pb.id,
            );
            assert!(
                pb.system_prompt.contains("STAGE COMPLETE"),
                "playbook '{}' system prompt must include STAGE COMPLETE protocol",
                pb.id,
            );
            assert!(
                pb.system_prompt.contains("SCAN COMPLETE"),
                "playbook '{}' system prompt must include SCAN COMPLETE protocol",
                pb.id,
            );
        }
    }

    #[test]
    fn test_get_playbook_default() {
        let pb = get_playbook("mcp_security_audit");
        assert!(pb.is_some(), "mcp_security_audit must be the default playbook");
        let pb = pb.unwrap();
        assert_eq!(pb.name, "MCP Security Audit");
        assert_eq!(pb.stages.len(), 5);
    }

    #[test]
    fn test_get_playbook_nonexistent() {
        assert!(
            get_playbook("nonexistent").is_none(),
            "nonexistent playbook should return None",
        );
    }

    #[test]
    fn test_playbook_summaries_include_cost() {
        let summaries = get_playbook_summaries();
        assert_eq!(summaries.len(), 6);
        for summary in &summaries {
            assert!(
                summary.estimated_cost_usd > 0.0,
                "playbook '{}' must have a positive estimated cost",
                summary.id,
            );
            assert!(
                summary.stage_count > 0,
                "playbook '{}' summary must have stage_count > 0",
                summary.id,
            );
            assert!(
                summary.estimated_duration_secs > 0,
                "playbook '{}' summary must have estimated_duration_secs > 0",
                summary.id,
            );
        }
    }

    #[test]
    fn test_all_playbook_ids_unique() {
        let playbooks = get_all_playbooks();
        let mut ids: Vec<&str> = playbooks.iter().map(|p| p.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 6, "all playbook IDs must be unique");
    }

    #[test]
    fn test_playbook_stages_have_key_tools() {
        for pb in get_all_playbooks() {
            for stage in &pb.stages {
                assert!(
                    !stage.key_tools.is_empty(),
                    "stage '{}' in playbook '{}' must have at least one key tool",
                    stage.name,
                    pb.id,
                );
            }
        }
    }

    #[test]
    fn test_full_audit_has_higher_limits() {
        let full = get_playbook("full_audit").unwrap();
        let mcp = get_playbook("mcp_security_audit").unwrap();
        assert!(
            full.estimated_tool_calls >= 200,
            "full_audit should allow at least 200 tool calls",
        );
        assert!(
            full.estimated_duration_secs >= 1200,
            "full_audit should estimate at least 20 minutes",
        );
        assert!(
            full.estimated_tool_calls > mcp.estimated_tool_calls,
            "full_audit should have more tool calls than individual playbooks",
        );
    }

    #[test]
    fn test_playbook_serialization_roundtrip() {
        let pb = get_playbook("mcp_security_audit").unwrap();
        let json = serde_json::to_string(&pb).expect("serialize");
        let restored: ScanPlaybook = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.id, pb.id);
        assert_eq!(restored.stages.len(), pb.stages.len());
        assert_eq!(restored.system_prompt, pb.system_prompt);
    }

    #[test]
    fn test_credential_exposure_safety_rule() {
        let pb = get_playbook("credential_exposure").unwrap();
        assert!(
            pb.system_prompt.contains("NEVER read, display, log, or output actual credential"),
            "credential_exposure must include the safety rule about never displaying secrets",
        );
    }
}
