use serde::{Deserialize, Serialize};

use super::capabilities::{infer_capabilities, ServerCapabilities};
use super::detection::{discover_all_servers, DiscoveredServer};
use super::health::{get_server_health, HealthWarning};
use crate::state::{AppState, ReputationResult, ScanResult, ServerProfileSummary};

const LEARNING_EVENT_THRESHOLD: f64 = 100.0;

/// Composite data model for a single tool card displayed on the My Tools page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCardData {
    pub server_name: String,
    pub client_name: String,
    pub client_app: String,
    pub is_wrapped: bool,
    pub trust_level: String,
    pub trust_customized: bool,
    pub behavioral_status: String,
    pub learning_progress: f32,
    pub event_count_today: u32,
    pub blocked_count_today: u32,
    pub last_unusual_activity: Option<String>,
    pub anomaly_score_current: f64,
    pub capabilities: ServerCapabilities,
    pub health_warnings: Vec<HealthWarning>,
    pub guard_name: Option<String>,
    pub guard_enabled: Option<bool>,
    pub scan_status: Option<String>,
    pub scan_findings_count: Option<u32>,
}

/// Infer trust level from policy rules matching `trust.{server_name}.*`.
fn infer_trust_level_from_rules(
    server_name: &str,
    policy_rules: &[crate::state::PolicyRule],
) -> (String, bool) {
    let prefix = format!("trust.{}.", sanitize_server_name(server_name));
    let trust_rules: Vec<&crate::state::PolicyRule> = policy_rules
        .iter()
        .filter(|r| r.name.starts_with(&prefix) && !r.name.ends_with(".sensitive-paths"))
        .collect();

    if trust_rules.is_empty() {
        return ("standard".to_string(), false);
    }

    let avg_priority =
        trust_rules.iter().map(|r| r.priority as f64).sum::<f64>() / trust_rules.len() as f64;

    let base_level = if avg_priority >= 500.0 {
        "restricted"
    } else if avg_priority >= 400.0 {
        "cautious"
    } else if avg_priority >= 300.0 {
        "standard"
    } else {
        "trusted"
    };

    // Check customization: see if rule count matches expected canonical count (7 categories)
    // A simple heuristic: canonical sets have exactly 7 rules (or 8 for restricted with tool-call-list-only)
    let expected_count = if base_level == "restricted" { 8 } else { 7 };
    let customized = trust_rules.len() != expected_count;

    (base_level.to_string(), customized)
}

/// Sanitize server name for use in rule key lookups.
fn sanitize_server_name(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .replace(' ', "-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Count today's events for a server from the event buffer.
fn count_today_events(state: &AppState, server_name: &str) -> (u32, u32) {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let buffer = match state.event_buffer.lock() {
        Ok(b) => b,
        Err(_) => return (0, 0),
    };

    let mut total = 0u32;
    let mut blocked = 0u32;
    for event in buffer.iter() {
        if event.server_name == server_name && event.timestamp.starts_with(&today) {
            total += 1;
            if event.decision == "block" || event.decision == "deny" {
                blocked += 1;
            }
        }
    }
    (total, blocked)
}

/// Find the most recent unusual activity timestamp for a server.
fn find_last_unusual_activity(state: &AppState, server_name: &str) -> Option<String> {
    let buffer = match state.event_buffer.lock() {
        Ok(b) => b,
        Err(_) => return None,
    };

    buffer
        .iter()
        .rev()
        .find(|e| {
            e.server_name == server_name
                && (e.risk_level == "high" || e.risk_level == "critical")
        })
        .map(|e| e.timestamp.clone())
}

/// Assemble a single tool card from multiple data sources.
pub fn assemble_tool_card(
    server: &DiscoveredServer,
    profiles: &[ServerProfileSummary],
    policy_rules: &[crate::state::PolicyRule],
    guards: &[crate::state::GuardSummary],
    scan_result: Option<&ScanResult>,
    reputation: Option<&ReputationResult>,
    state: &AppState,
) -> ToolCardData {
    // Trust level
    let (trust_level, trust_customized) =
        infer_trust_level_from_rules(&server.server_name, policy_rules);

    // Behavioral profile
    let profile = profiles
        .iter()
        .find(|p| p.server_name == server.server_name);

    let behavioral_status = profile
        .map(|p| p.status.clone())
        .unwrap_or_else(|| "learning".to_string());

    let learning_progress = profile
        .map(|p| (p.total_calls as f64 / LEARNING_EVENT_THRESHOLD).min(1.0) as f32)
        .unwrap_or(0.0);

    let anomaly_score_current = profile.map(|p| p.anomaly_score).unwrap_or(0.0);

    // Events today
    let (event_count_today, blocked_count_today) =
        count_today_events(state, &server.server_name);

    // Last unusual activity
    let last_unusual_activity = find_last_unusual_activity(state, &server.server_name);

    // Capabilities
    let capabilities = infer_capabilities(&server.server_name, &server.command);

    // Health warnings
    let health_warnings = get_server_health(
        &server.server_name,
        server.wrapped,
        profile,
        scan_result,
        reputation,
    );

    // Guard
    let guard = guards.iter().find(|g| {
        g.name == server.server_name || g.name.contains(&server.server_name)
    });

    let guard_name = guard.map(|g| g.name.clone());
    let guard_enabled = guard.map(|g| g.enabled);

    // Scan
    let scan_status = scan_result.map(|s| s.status.clone());
    let scan_findings_count = scan_result.map(|s| s.total_findings);

    ToolCardData {
        server_name: server.server_name.clone(),
        client_name: server.client_name.clone(),
        client_app: server.client_display_name.clone(),
        is_wrapped: server.wrapped,
        trust_level,
        trust_customized,
        behavioral_status,
        learning_progress,
        event_count_today,
        blocked_count_today,
        last_unusual_activity,
        anomaly_score_current,
        capabilities,
        health_warnings,
        guard_name,
        guard_enabled,
        scan_status,
        scan_findings_count,
    }
}

/// Assemble tool cards for all discovered servers.
/// Returns sorted: wrapped first (alphabetical), then unwrapped (alphabetical).
pub fn assemble_all_tool_cards(
    profiles: &[ServerProfileSummary],
    policy_rules: &[crate::state::PolicyRule],
    guards: &[crate::state::GuardSummary],
    state: &AppState,
) -> Vec<ToolCardData> {
    let servers = discover_all_servers();

    let mut cards: Vec<ToolCardData> = servers
        .iter()
        .map(|server| {
            assemble_tool_card(server, profiles, policy_rules, guards, None, None, state)
        })
        .collect();

    // Sort: wrapped first, then alphabetical by server_name
    cards.sort_by(|a, b| {
        b.is_wrapped
            .cmp(&a.is_wrapped)
            .then_with(|| a.server_name.cmp(&b.server_name))
    });

    cards
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::PolicyRule;

    #[test]
    fn test_infer_trust_level_no_rules() {
        let (level, customized) = infer_trust_level_from_rules("test-server", &[]);
        assert_eq!(level, "standard");
        assert!(!customized);
    }

    #[test]
    fn test_infer_trust_level_standard() {
        let rules: Vec<PolicyRule> = ["tool-call", "file-read-project", "file-read-external",
            "file-write", "shell-exec", "network-access", "sensitive-paths"]
            .iter()
            .map(|cat| PolicyRule {
                name: format!("trust.test-server.{}", cat),
                description: String::new(),
                action: "prompt".to_string(),
                resource: "*".to_string(),
                pattern: "*".to_string(),
                priority: 300,
                enabled: true,
            })
            .collect();

        let (level, _customized) = infer_trust_level_from_rules("test-server", &rules);
        assert_eq!(level, "standard");
    }

    #[test]
    fn test_infer_trust_level_trusted() {
        let rules: Vec<PolicyRule> = ["tool-call", "file-read-project", "file-read-external",
            "file-write", "shell-exec", "network-access", "sensitive-paths"]
            .iter()
            .map(|cat| PolicyRule {
                name: format!("trust.my-server.{}", cat),
                description: String::new(),
                action: "allow".to_string(),
                resource: "*".to_string(),
                pattern: "*".to_string(),
                priority: 200,
                enabled: true,
            })
            .collect();

        let (level, _) = infer_trust_level_from_rules("my-server", &rules);
        assert_eq!(level, "trusted");
    }

    #[test]
    fn test_infer_trust_level_restricted() {
        let rules: Vec<PolicyRule> = ["tool-call", "file-read-project", "file-read-external",
            "file-write", "shell-exec", "network-access", "sensitive-paths", "tool-call-list-only"]
            .iter()
            .map(|cat| PolicyRule {
                name: format!("trust.locked-server.{}", cat),
                description: String::new(),
                action: "block".to_string(),
                resource: "*".to_string(),
                pattern: "*".to_string(),
                priority: 500,
                enabled: true,
            })
            .collect();

        let (level, _) = infer_trust_level_from_rules("locked-server", &rules);
        assert_eq!(level, "restricted");
    }

    #[test]
    fn test_sanitize_server_name() {
        assert_eq!(sanitize_server_name("My Server"), "my-server");
        assert_eq!(sanitize_server_name("  test_server  "), "test_server");
        assert_eq!(sanitize_server_name("server@123"), "server123");
    }

    #[test]
    fn test_assemble_tool_card_basic() {
        let server = DiscoveredServer {
            server_name: "filesystem".to_string(),
            client_name: "claude".to_string(),
            client_display_name: "Claude Desktop".to_string(),
            command: vec![
                "npx".to_string(),
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
            ],
            wrapped: true,
        };

        let state = AppState::default();
        let card = assemble_tool_card(
            &server,
            &[],
            &[],
            &[],
            None,
            None,
            &state,
        );

        assert_eq!(card.server_name, "filesystem");
        assert_eq!(card.client_name, "claude");
        assert!(card.is_wrapped);
        assert_eq!(card.trust_level, "standard");
        assert!(card.capabilities.can_read_files);
        assert_eq!(card.behavioral_status, "learning");
        assert_eq!(card.learning_progress, 0.0);
    }

    #[test]
    fn test_assemble_tool_card_with_profile() {
        let server = DiscoveredServer {
            server_name: "fetch".to_string(),
            client_name: "cursor".to_string(),
            client_display_name: "Cursor".to_string(),
            command: vec![
                "npx".to_string(),
                "@modelcontextprotocol/server-fetch".to_string(),
            ],
            wrapped: false,
        };

        let profiles = vec![ServerProfileSummary {
            server_name: "fetch".to_string(),
            tools_count: 1,
            total_calls: 75,
            anomaly_score: 0.2,
            status: "learning".to_string(),
            last_activity: chrono::Utc::now().to_rfc3339(),
        }];

        let state = AppState::default();
        let card = assemble_tool_card(
            &server,
            &profiles,
            &[],
            &[],
            None,
            None,
            &state,
        );

        assert_eq!(card.behavioral_status, "learning");
        assert!((card.learning_progress - 0.75).abs() < 0.01);
        assert!((card.anomaly_score_current - 0.2).abs() < 0.001);
        // Should have "not protected" warning since not wrapped
        assert!(card.health_warnings.iter().any(|w| w.action_type == "wrap"));
    }

    #[test]
    fn test_tool_card_sort_order() {
        let state = AppState::default();
        // We can't easily test assemble_all_tool_cards without actual config files,
        // but we can test the sort logic directly
        let mut cards = vec![
            ToolCardData {
                server_name: "zebra".to_string(),
                is_wrapped: false,
                ..make_default_card()
            },
            ToolCardData {
                server_name: "alpha".to_string(),
                is_wrapped: true,
                ..make_default_card()
            },
            ToolCardData {
                server_name: "beta".to_string(),
                is_wrapped: true,
                ..make_default_card()
            },
            ToolCardData {
                server_name: "apple".to_string(),
                is_wrapped: false,
                ..make_default_card()
            },
        ];

        cards.sort_by(|a, b| {
            b.is_wrapped
                .cmp(&a.is_wrapped)
                .then_with(|| a.server_name.cmp(&b.server_name))
        });

        assert_eq!(cards[0].server_name, "alpha");
        assert_eq!(cards[1].server_name, "beta");
        assert_eq!(cards[2].server_name, "apple");
        assert_eq!(cards[3].server_name, "zebra");
    }

    fn make_default_card() -> ToolCardData {
        ToolCardData {
            server_name: String::new(),
            client_name: "claude".to_string(),
            client_app: "Claude Desktop".to_string(),
            is_wrapped: false,
            trust_level: "standard".to_string(),
            trust_customized: false,
            behavioral_status: "learning".to_string(),
            learning_progress: 0.0,
            event_count_today: 0,
            blocked_count_today: 0,
            last_unusual_activity: None,
            anomaly_score_current: 0.0,
            capabilities: ServerCapabilities::default(),
            health_warnings: Vec::new(),
            guard_name: None,
            guard_enabled: None,
            scan_status: None,
            scan_findings_count: None,
        }
    }
}
