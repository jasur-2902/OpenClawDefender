use serde::{Deserialize, Serialize};
use crate::state::AuditEvent;

// ---------------------------------------------------------------------------
// Kill Chain Narrative types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainNarrative {
    pub pattern_name: String,
    pub summary: String,
    pub steps: Vec<KillChainStep>,
    pub verdict: String,
    pub outcome: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStep {
    pub step_number: u32,
    pub timestamp: String,
    pub description: String,
    pub severity: String,
    pub was_blocked: bool,
    pub event_id: String,
}

/// Time window to look back for kill chain patterns (60 seconds).
const KILL_CHAIN_WINDOW_SECS: i64 = 60;

// ---------------------------------------------------------------------------
// Pattern detection
// ---------------------------------------------------------------------------

/// Check whether the current event completes a kill chain pattern when
/// combined with recent events from the same server.
///
/// Patterns detected:
/// 1. Credential theft: sensitive file read -> network connection
/// 2. Recon-to-theft: multiple directory listings -> credential file access
/// 3. Staging exfiltration: file copy to temp -> outbound network
/// 4. Injection chain: sampling request -> unauthorized tool call
/// 5. Privilege escalation: shell command -> sensitive file write
pub fn check_kill_chain(event: &AuditEvent, recent_events: &[AuditEvent]) -> Option<KillChainNarrative> {
    // Gather recent events from the SAME server within the time window
    let server = &event.server_name;
    let event_time = chrono::DateTime::parse_from_rfc3339(&event.timestamp).ok()?;

    let mut server_events: Vec<&AuditEvent> = recent_events
        .iter()
        .filter(|e| {
            e.server_name == *server
                && e.id != event.id
                && chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                    .map(|t| (event_time - t).num_seconds().abs() <= KILL_CHAIN_WINDOW_SECS)
                    .unwrap_or(false)
        })
        .collect();

    // Sort by timestamp ascending
    server_events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Add current event at the end for pattern matching
    // (We will reference it directly when needed)

    // Try each pattern in priority order
    if let Some(n) = detect_credential_exfiltration(event, &server_events) {
        return Some(n);
    }
    if let Some(n) = detect_recon_credential_access(event, &server_events) {
        return Some(n);
    }
    if let Some(n) = detect_staging_exfiltration(event, &server_events) {
        return Some(n);
    }
    if let Some(n) = detect_injection_chain(event, &server_events) {
        return Some(n);
    }
    if let Some(n) = detect_privilege_escalation(event, &server_events) {
        return Some(n);
    }

    None
}

// ---------------------------------------------------------------------------
// Pattern 1: Credential exfiltration
// Step 1: Sensitive file read (SSH/AWS/env)
// Step 2: Network connection (current event)
// ---------------------------------------------------------------------------

fn detect_credential_exfiltration(current: &AuditEvent, recent: &[&AuditEvent]) -> Option<KillChainNarrative> {
    // Current event must be network-related
    if !is_network_event(current) {
        return None;
    }

    // Look for a prior sensitive file read
    let cred_read = recent.iter().find(|e| is_sensitive_file_read(e))?;

    let any_blocked = is_blocked(current) || is_blocked(cred_read);
    let verdict = if any_blocked {
        format!(
            "{} read a credentials file and then tried to send data externally. I blocked the chain.",
            current.server_name
        )
    } else {
        format!(
            "{} read a credentials file and then connected to an external server. This looks like credential theft.",
            current.server_name
        )
    };

    Some(KillChainNarrative {
        pattern_name: "credential_exfiltration".to_string(),
        summary: format!(
            "I detected a credential theft pattern from {}. First it read sensitive credentials, then it tried to send data out.",
            current.server_name
        ),
        steps: vec![
            KillChainStep {
                step_number: 1,
                timestamp: cred_read.timestamp.clone(),
                description: format!("Read sensitive credentials: {}", resource_display(cred_read)),
                severity: "dangerous".to_string(),
                was_blocked: is_blocked(cred_read),
                event_id: cred_read.id.clone(),
            },
            KillChainStep {
                step_number: 2,
                timestamp: current.timestamp.clone(),
                description: format!("Attempted network connection: {}", resource_display(current)),
                severity: "dangerous".to_string(),
                was_blocked: is_blocked(current),
                event_id: current.id.clone(),
            },
        ],
        verdict,
        outcome: if any_blocked { "Chain blocked".to_string() } else { "Chain completed — investigate".to_string() },
        confidence: 0.85,
    })
}

// ---------------------------------------------------------------------------
// Pattern 2: Recon-to-credential-access
// Step 1: Multiple directory listings (3+)
// Step 2: Sensitive file read (current event)
// ---------------------------------------------------------------------------

fn detect_recon_credential_access(current: &AuditEvent, recent: &[&AuditEvent]) -> Option<KillChainNarrative> {
    if !is_sensitive_file_read(current) {
        return None;
    }

    let listings: Vec<&&AuditEvent> = recent.iter().filter(|e| is_directory_listing(e)).collect();
    if listings.len() < 3 {
        return None;
    }

    let any_blocked = is_blocked(current);
    let verdict = if any_blocked {
        format!(
            "{} scanned your files then went for credentials. I blocked it.",
            current.server_name
        )
    } else {
        format!(
            "{} performed reconnaissance by listing directories, then accessed sensitive credentials.",
            current.server_name
        )
    };

    let mut steps: Vec<KillChainStep> = listings
        .iter()
        .enumerate()
        .take(3)
        .map(|(i, e)| KillChainStep {
            step_number: (i + 1) as u32,
            timestamp: e.timestamp.clone(),
            description: format!("Directory listing: {}", resource_display(e)),
            severity: "suspicious".to_string(),
            was_blocked: is_blocked(e),
            event_id: e.id.clone(),
        })
        .collect();

    steps.push(KillChainStep {
        step_number: steps.len() as u32 + 1,
        timestamp: current.timestamp.clone(),
        description: format!("Accessed sensitive file: {}", resource_display(current)),
        severity: "dangerous".to_string(),
        was_blocked: any_blocked,
        event_id: current.id.clone(),
    });

    Some(KillChainNarrative {
        pattern_name: "recon_credential_access".to_string(),
        summary: format!(
            "I detected a reconnaissance-to-theft pattern from {}. It listed multiple directories before targeting credentials.",
            current.server_name
        ),
        steps,
        verdict,
        outcome: if any_blocked { "Chain blocked".to_string() } else { "Chain completed — investigate".to_string() },
        confidence: 0.75,
    })
}

// ---------------------------------------------------------------------------
// Pattern 3: Data staging exfiltration
// Step 1: File write to temp directory
// Step 2: Network connection (current event)
// ---------------------------------------------------------------------------

fn detect_staging_exfiltration(current: &AuditEvent, recent: &[&AuditEvent]) -> Option<KillChainNarrative> {
    if !is_network_event(current) {
        return None;
    }

    let temp_write = recent.iter().find(|e| is_temp_file_write(e))?;

    let any_blocked = is_blocked(current) || is_blocked(temp_write);
    let verdict = if any_blocked {
        format!(
            "{} staged data in a temporary location and tried to send it out. I blocked the connection.",
            current.server_name
        )
    } else {
        format!(
            "{} wrote data to a temporary location then connected to an external server. This looks like data staging for exfiltration.",
            current.server_name
        )
    };

    Some(KillChainNarrative {
        pattern_name: "data_staging_exfiltration".to_string(),
        summary: format!(
            "I detected a data staging pattern from {}. It wrote to a temp location then tried to connect externally.",
            current.server_name
        ),
        steps: vec![
            KillChainStep {
                step_number: 1,
                timestamp: temp_write.timestamp.clone(),
                description: format!("Staged data to temp: {}", resource_display(temp_write)),
                severity: "suspicious".to_string(),
                was_blocked: is_blocked(temp_write),
                event_id: temp_write.id.clone(),
            },
            KillChainStep {
                step_number: 2,
                timestamp: current.timestamp.clone(),
                description: format!("Attempted outbound connection: {}", resource_display(current)),
                severity: "dangerous".to_string(),
                was_blocked: is_blocked(current),
                event_id: current.id.clone(),
            },
        ],
        verdict,
        outcome: if any_blocked { "Chain blocked".to_string() } else { "Chain completed — investigate".to_string() },
        confidence: 0.80,
    })
}

// ---------------------------------------------------------------------------
// Pattern 4: Injection chain
// Step 1: Sampling request
// Step 2: Unauthorized tool call (current event)
// ---------------------------------------------------------------------------

fn detect_injection_chain(current: &AuditEvent, recent: &[&AuditEvent]) -> Option<KillChainNarrative> {
    // Current event should look like an unauthorized or suspicious tool call
    let current_action_lower = current.action.to_lowercase();
    if !(current_action_lower.contains("tool") || current_action_lower.contains("call")) {
        return None;
    }

    let sampling = recent.iter().find(|e| is_sampling_event(e))?;

    let any_blocked = is_blocked(current);
    let verdict = if any_blocked {
        format!(
            "{} sent an AI sampling request then tried to call a tool it should not have. I blocked the tool call.",
            current.server_name
        )
    } else {
        format!(
            "{} used an AI sampling request followed by a suspicious tool call. This could be a prompt injection attack.",
            current.server_name
        )
    };

    Some(KillChainNarrative {
        pattern_name: "injection_chain".to_string(),
        summary: format!(
            "I detected a potential injection chain from {}. An AI sampling request was followed by a suspicious tool call.",
            current.server_name
        ),
        steps: vec![
            KillChainStep {
                step_number: 1,
                timestamp: sampling.timestamp.clone(),
                description: "Sent AI sampling/createMessage request".to_string(),
                severity: "suspicious".to_string(),
                was_blocked: is_blocked(sampling),
                event_id: sampling.id.clone(),
            },
            KillChainStep {
                step_number: 2,
                timestamp: current.timestamp.clone(),
                description: format!("Attempted unauthorized tool call: {}", current.action),
                severity: "dangerous".to_string(),
                was_blocked: any_blocked,
                event_id: current.id.clone(),
            },
        ],
        verdict,
        outcome: if any_blocked { "Chain blocked".to_string() } else { "Chain completed — investigate".to_string() },
        confidence: 0.70,
    })
}

// ---------------------------------------------------------------------------
// Pattern 5: Privilege escalation
// Step 1: Shell command execution
// Step 2: Sensitive file write (current event)
// ---------------------------------------------------------------------------

fn detect_privilege_escalation(current: &AuditEvent, recent: &[&AuditEvent]) -> Option<KillChainNarrative> {
    if !is_sensitive_file_write(current) {
        return None;
    }

    let shell_cmd = recent.iter().find(|e| is_shell_command(e))?;

    let any_blocked = is_blocked(current) || is_blocked(shell_cmd);
    let verdict = if any_blocked {
        format!(
            "{} tried to escalate privileges by modifying system files. I blocked the write.",
            current.server_name
        )
    } else {
        format!(
            "{} executed a shell command and then wrote to a sensitive system location. This looks like privilege escalation.",
            current.server_name
        )
    };

    Some(KillChainNarrative {
        pattern_name: "privilege_escalation".to_string(),
        summary: format!(
            "I detected a privilege escalation attempt from {}. A shell command was followed by a write to a system directory.",
            current.server_name
        ),
        steps: vec![
            KillChainStep {
                step_number: 1,
                timestamp: shell_cmd.timestamp.clone(),
                description: format!("Executed shell command: {}", resource_display(shell_cmd)),
                severity: "suspicious".to_string(),
                was_blocked: is_blocked(shell_cmd),
                event_id: shell_cmd.id.clone(),
            },
            KillChainStep {
                step_number: 2,
                timestamp: current.timestamp.clone(),
                description: format!("Attempted write to system path: {}", resource_display(current)),
                severity: "dangerous".to_string(),
                was_blocked: is_blocked(current),
                event_id: current.id.clone(),
            },
        ],
        verdict,
        outcome: if any_blocked { "Chain blocked".to_string() } else { "Chain completed — investigate".to_string() },
        confidence: 0.80,
    })
}

// ---------------------------------------------------------------------------
// Event classification helpers
// ---------------------------------------------------------------------------

fn is_network_event(event: &AuditEvent) -> bool {
    let t = event.event_type.to_lowercase();
    let a = event.action.to_lowercase();
    t.contains("network") || a.contains("network") || a.contains("connect") || a.contains("outbound")
}

fn is_sensitive_file_read(event: &AuditEvent) -> bool {
    let resource = event.resource.as_deref().unwrap_or("");
    let details = &event.details;
    let r_lower = resource.to_lowercase();
    let d_lower = details.to_lowercase();

    let sensitive_patterns = [
        ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa",
        ".aws/credentials", ".aws/config",
        ".env", "credentials", "secrets", "token",
        "login data", "cookies.sqlite", "logins.json",
    ];

    let is_read = {
        let a = event.action.to_lowercase();
        a.contains("read") || a.contains("file read") || event.tool_name.as_deref().unwrap_or("") == "read_file"
    };

    is_read && sensitive_patterns.iter().any(|p| r_lower.contains(p) || d_lower.contains(p))
}

fn is_directory_listing(event: &AuditEvent) -> bool {
    let a = event.action.to_lowercase();
    a.contains("list") || a.contains("directory") || a.contains("ls") || a.contains("discovery")
}

fn is_temp_file_write(event: &AuditEvent) -> bool {
    let resource = event.resource.as_deref().unwrap_or("").to_lowercase();
    let a = event.action.to_lowercase();
    let is_write = a.contains("write") || a.contains("create") || event.tool_name.as_deref().unwrap_or("") == "write_file";
    let is_temp = resource.contains("/tmp/") || resource.contains("/temp/") || resource.contains("\\temp\\");
    is_write && is_temp
}

fn is_sampling_event(event: &AuditEvent) -> bool {
    let a = event.action.to_lowercase();
    a.contains("sampling") || a.contains("createmessage") || a.contains("create_message")
}

fn is_shell_command(event: &AuditEvent) -> bool {
    let a = event.action.to_lowercase();
    let t = event.tool_name.as_deref().unwrap_or("").to_lowercase();
    a.contains("shell") || a.contains("exec") || a.contains("command") || t.contains("bash") || t.contains("shell")
}

fn is_sensitive_file_write(event: &AuditEvent) -> bool {
    let resource = event.resource.as_deref().unwrap_or("").to_lowercase();
    let a = event.action.to_lowercase();
    let is_write = a.contains("write") || a.contains("create") || event.tool_name.as_deref().unwrap_or("") == "write_file";
    let sensitive_paths = ["/usr/local/bin", "/etc/", "/usr/bin", "/sbin", "/Library/LaunchDaemons", "/Library/LaunchAgents"];
    is_write && sensitive_paths.iter().any(|p| resource.contains(&p.to_lowercase()))
}

fn is_blocked(event: &AuditEvent) -> bool {
    let d = event.decision.to_lowercase();
    d == "blocked" || d == "denied" || d == "block"
}

fn resource_display(event: &AuditEvent) -> String {
    event.resource.clone().unwrap_or_else(|| event.action.clone())
}
