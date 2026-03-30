use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::{AuditEvent, ServerProfileSummary};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub rec_type: String,
    pub description: String,
    pub action_label: String,
    pub action_type: String,
    pub action_params: Option<serde_json::Value>,
    pub priority: u32,
    pub dismissed: bool,
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate recommendations based on event history and profile data.
pub fn generate_recommendations(
    events: &[AuditEvent],
    profiles: &[ServerProfileSummary],
) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();

    // 1. Frequent prompts: same server+action prompted >5 times.
    check_frequent_prompts(events, &mut recommendations);

    // 2. Permission tightening: server only accesses files in a specific directory.
    check_permission_tightening(events, &mut recommendations);

    // 3. Trust suggestions: consistent server with low anomaly, >30 days equivalent data.
    check_trust_suggestions(profiles, &mut recommendations);

    // 4. Learning completion: profile status changed from "learning" to "active".
    check_learning_completion(profiles, &mut recommendations);

    // 5. Unwrapped servers: detected but not monitored.
    check_unwrapped_servers(profiles, events, &mut recommendations);

    // Sort by priority (lower number = higher priority).
    recommendations.sort_by_key(|r| r.priority);

    recommendations
}

/// Execute a recommendation action. Returns a success message in Claw's voice.
pub fn execute_recommendation(rec: &Recommendation) -> Result<String, String> {
    match rec.action_type.as_str() {
        "add_allow_rule" => {
            let server = rec
                .action_params
                .as_ref()
                .and_then(|p| p.get("server_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let action = rec
                .action_params
                .as_ref()
                .and_then(|p| p.get("action"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(format!(
                "Done. I've added a permanent allow rule for {} to {}. No more prompts for that one.",
                server, action
            ))
        }
        "restrict_territory" => {
            let server = rec
                .action_params
                .as_ref()
                .and_then(|p| p.get("server_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let directory = rec
                .action_params
                .as_ref()
                .and_then(|p| p.get("directory"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            Ok(format!(
                "Done. I've restricted {} to only access {}. If it tries to reach outside, I'll block it.",
                server, directory
            ))
        }
        "change_trust_level" => {
            let server = rec
                .action_params
                .as_ref()
                .and_then(|p| p.get("server_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let level = rec
                .action_params
                .as_ref()
                .and_then(|p| p.get("trust_level"))
                .and_then(|v| v.as_str())
                .unwrap_or("trusted");
            Ok(format!(
                "Done. I've moved {} to {} trust. It's earned it through consistent behavior.",
                server, level
            ))
        }
        "acknowledge_learning" => Ok(
            "Noted. The behavioral profile is now active and I'll watch for deviations.".to_string(),
        ),
        "wrap_servers" => Ok(
            "I'll start monitoring those servers. You'll see them appear in your tool list shortly."
                .to_string(),
        ),
        _ => Err(format!("Unknown action type: {}", rec.action_type)),
    }
}

// ---------------------------------------------------------------------------
// Individual recommendation checks
// ---------------------------------------------------------------------------

fn check_frequent_prompts(events: &[AuditEvent], recs: &mut Vec<Recommendation>) {
    // Count server+action combos that were prompted.
    let mut prompt_counts: HashMap<(String, String), u64> = HashMap::new();

    for event in events {
        if event.decision == "prompted" || event.decision == "prompt" {
            let key = (event.server_name.clone(), event.action.clone());
            *prompt_counts.entry(key).or_insert(0) += 1;
        }
    }

    for ((server, action), count) in &prompt_counts {
        if *count > 5 {
            recs.push(Recommendation {
                id: format!("freq-prompt-{}-{}", server, action),
                rec_type: "frequent_prompt".to_string(),
                description: format!(
                    "You've allowed {} to {} {} times this week. Want me to add a permanent allow rule so you don't have to keep approving it?",
                    server, action, count
                ),
                action_label: "Add allow rule".to_string(),
                action_type: "add_allow_rule".to_string(),
                action_params: Some(serde_json::json!({
                    "server_name": server,
                    "action": action,
                })),
                priority: 1,
                dismissed: false,
            });
        }
    }
}

fn check_permission_tightening(events: &[AuditEvent], recs: &mut Vec<Recommendation>) {
    // Group file access events by server and find dominant directories.
    let mut server_dirs: HashMap<String, HashMap<String, u64>> = HashMap::new();

    for event in events {
        if let Some(ref resource) = event.resource {
            if let Some(dir) = resource.rsplit_once('/').map(|(d, _)| d.to_string()) {
                let top = top_directory_2(&dir);
                *server_dirs
                    .entry(event.server_name.clone())
                    .or_default()
                    .entry(top)
                    .or_insert(0) += 1;
            }
        }
    }

    for (server, dirs) in &server_dirs {
        let total: u64 = dirs.values().sum();
        if total < 10 {
            continue;
        }

        // If one directory accounts for >80% of access, suggest restriction.
        if let Some((dir, count)) = dirs.iter().max_by_key(|(_, c)| *c) {
            let pct = (*count as f64 / total as f64) * 100.0;
            if pct >= 80.0 {
                recs.push(Recommendation {
                    id: format!("restrict-{}-{}", server, dir.replace('/', "-")),
                    rec_type: "permission_tightening".to_string(),
                    description: format!(
                        "Based on {}'s behavior, it only needs access to {}. I could restrict it to just that area for tighter security.",
                        server, dir
                    ),
                    action_label: "Restrict access".to_string(),
                    action_type: "restrict_territory".to_string(),
                    action_params: Some(serde_json::json!({
                        "server_name": server,
                        "directory": dir,
                    })),
                    priority: 2,
                    dismissed: false,
                });
            }
        }
    }
}

fn check_trust_suggestions(profiles: &[ServerProfileSummary], recs: &mut Vec<Recommendation>) {
    for profile in profiles {
        // Consistent server with low anomaly and significant history.
        if profile.anomaly_score < 0.1 && profile.total_calls > 500 && profile.status == "active" {
            recs.push(Recommendation {
                id: format!("trust-{}", profile.server_name),
                rec_type: "trust_suggestion".to_string(),
                description: format!(
                    "{} has been completely consistent with {} events logged and a near-zero anomaly score. You could safely move it to Trusted.",
                    profile.server_name, profile.total_calls
                ),
                action_label: "Move to Trusted".to_string(),
                action_type: "change_trust_level".to_string(),
                action_params: Some(serde_json::json!({
                    "server_name": profile.server_name,
                    "trust_level": "trusted",
                })),
                priority: 3,
                dismissed: false,
            });
        }
    }
}

fn check_learning_completion(profiles: &[ServerProfileSummary], recs: &mut Vec<Recommendation>) {
    for profile in profiles {
        // Profile recently transitioned from learning to active.
        if profile.status == "active" && profile.total_calls >= 100 && profile.total_calls < 150 {
            recs.push(Recommendation {
                id: format!("learning-done-{}", profile.server_name),
                rec_type: "learning_completion".to_string(),
                description: format!(
                    "{}'s behavioral profile is ready. I now know what normal looks like for this tool and I'll flag anything unusual.",
                    profile.server_name
                ),
                action_label: "Got it".to_string(),
                action_type: "acknowledge_learning".to_string(),
                action_params: Some(serde_json::json!({
                    "server_name": profile.server_name,
                })),
                priority: 4,
                dismissed: false,
            });
        }
    }
}

fn check_unwrapped_servers(
    _profiles: &[ServerProfileSummary],
    events: &[AuditEvent],
    recs: &mut Vec<Recommendation>,
) {
    // Find servers that appear in events but have decision "unmonitored" or no profile.
    let mut unmonitored: HashMap<String, u64> = HashMap::new();
    for event in events {
        if event.decision == "unmonitored" || event.decision == "passthrough" {
            *unmonitored
                .entry(event.server_name.clone())
                .or_insert(0) += 1;
        }
    }

    if !unmonitored.is_empty() {
        let count = unmonitored.len();
        let names: Vec<String> = unmonitored.keys().take(3).cloned().collect();
        recs.push(Recommendation {
            id: "unwrapped-servers".to_string(),
            rec_type: "unwrapped_servers".to_string(),
            description: format!(
                "I found {} server{} that aren't monitored yet{}. Want me to start watching {}?",
                count,
                if count == 1 { "" } else { "s" },
                if !names.is_empty() {
                    format!(" ({})", names.join(", "))
                } else {
                    String::new()
                },
                if count == 1 { "it" } else { "them" }
            ),
            action_label: "Wrap servers".to_string(),
            action_type: "wrap_servers".to_string(),
            action_params: Some(serde_json::json!({
                "server_names": names,
            })),
            priority: 2,
            dismissed: false,
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn top_directory_2(path: &str) -> String {
    let path = path.trim_start_matches('/');
    let parts: Vec<&str> = path.split('/').collect();
    let depth = parts.len().min(2);
    if depth == 0 {
        return "/".to_string();
    }
    format!("/{}", parts[..depth].join("/"))
}
