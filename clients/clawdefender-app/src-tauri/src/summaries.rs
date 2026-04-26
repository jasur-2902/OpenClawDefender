use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::{AppState, AuditEvent, ServerProfileSummary};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSummary {
    pub territory: Vec<DirectorySummary>,
    pub common_tools: Vec<ToolUsageSummary>,
    pub network_summary: NetworkSummaryType,
    pub activity_pattern: ActivityPattern,
    pub learning_status: LearningStatusInfo,
    pub trust_recommendation: Option<String>,
    pub notable_observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectorySummary {
    pub path: String,
    pub percentage: f32,
    pub access_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageSummary {
    pub tool_name: String,
    pub percentage: f32,
    pub call_count: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NetworkSummaryType {
    Never,
    Regular {
        hosts: Vec<String>,
        total_connections: u64,
    },
    Rare {
        last_connection: String,
        host: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityPattern {
    pub avg_actions_per_hour: f32,
    pub hourly_data: Vec<f32>,
    pub peak_period: String,
    pub unusual_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStatusInfo {
    pub status: String,
    pub progress: f32,
    pub events_needed: u32,
}

/// Threshold of events before a profile transitions from learning to active.
const LEARNING_EVENT_THRESHOLD: u64 = 100;

// ---------------------------------------------------------------------------
// Tauri command
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn get_server_summary(
    server: String,
    state: tauri::State<'_, AppState>,
) -> Result<ServerSummary, String> {
    // Grab a snapshot of events for this server.
    let events: Vec<AuditEvent> = state
        .event_buffer
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?
        .iter()
        .filter(|e| e.server_name == server)
        .cloned()
        .collect();

    // Try to get the profile summary from the DB.
    let profile = tokio::task::spawn_blocking({
        let server = server.clone();
        move || crate::commands::read_profiles_from_db_for_server(&server)
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?;

    let territory = summarize_territory(&events);
    let common_tools = summarize_tools(&events);
    let network_summary = summarize_network(&events);
    let activity_pattern = summarize_activity(&events);
    let learning_status = build_learning_status(&profile);
    let trust_recommendation = compute_trust_recommendation(&events, &profile);
    let notable_observations = generate_observations(&events, &profile);

    Ok(ServerSummary {
        territory,
        common_tools,
        network_summary,
        activity_pattern,
        learning_status,
        trust_recommendation: Some(trust_recommendation),
        notable_observations,
    })
}

// ---------------------------------------------------------------------------
// Territory summarization
// ---------------------------------------------------------------------------

fn summarize_territory(events: &[AuditEvent]) -> Vec<DirectorySummary> {
    let mut dir_counts: HashMap<String, u64> = HashMap::new();

    for event in events {
        if let Some(ref resource) = event.resource {
            let dir = top_directory(resource, 2);
            *dir_counts.entry(dir).or_insert(0) += 1;
        }
    }

    if dir_counts.is_empty() {
        return vec![];
    }

    let total: u64 = dir_counts.values().sum();
    let mut sorted: Vec<(String, u64)> = dir_counts.into_iter().collect();
    sorted.sort_by_key(|x| std::cmp::Reverse(x.1));

    let mut result: Vec<DirectorySummary> = sorted
        .iter()
        .take(3)
        .map(|(path, count)| DirectorySummary {
            path: path.clone(),
            percentage: (*count as f32 / total as f32) * 100.0,
            access_count: *count,
        })
        .collect();

    // If paths outside top 3 account for >5%, add an "other" entry.
    let top3_total: u64 = sorted.iter().take(3).map(|(_, c)| c).sum();
    let remainder = total - top3_total;
    let remainder_pct = (remainder as f32 / total as f32) * 100.0;
    if remainder_pct > 5.0 {
        result.push(DirectorySummary {
            path: "(other)".to_string(),
            percentage: remainder_pct,
            access_count: remainder,
        });
    }

    result
}

/// Extract the top N directory components from a path.
fn top_directory(path: &str, levels: usize) -> String {
    let path = path.trim_start_matches('/');
    let parts: Vec<&str> = path.split('/').collect();
    let depth = parts.len().min(levels);
    if depth == 0 {
        return "/".to_string();
    }
    format!("/{}", parts[..depth].join("/"))
}

// ---------------------------------------------------------------------------
// Tool usage summarization
// ---------------------------------------------------------------------------

fn tool_description(name: &str) -> &str {
    match name {
        "read_file" => "Reads file contents",
        "write_file" => "Creates or modifies files",
        "list_directory" => "Lists directory contents",
        "search_files" => "Searches for files",
        "execute_command" | "run_command" => "Runs shell commands",
        "fetch" | "http_request" => "Makes HTTP requests",
        "query" | "sql_query" => "Runs database queries",
        "git_status" | "git_diff" | "git_commit" => "Git operations",
        "list_tools" => "Lists available tools",
        "create_directory" => "Creates directories",
        "move_file" => "Moves or renames files",
        "delete_file" => "Deletes files",
        _ => "Custom tool operation",
    }
}

fn summarize_tools(events: &[AuditEvent]) -> Vec<ToolUsageSummary> {
    let mut tool_counts: HashMap<String, u64> = HashMap::new();

    for event in events {
        if let Some(ref tool) = event.tool_name {
            *tool_counts.entry(tool.clone()).or_insert(0) += 1;
        }
    }

    if tool_counts.is_empty() {
        return vec![];
    }

    let total: u64 = tool_counts.values().sum();
    let mut sorted: Vec<(String, u64)> = tool_counts.into_iter().collect();
    sorted.sort_by_key(|x| std::cmp::Reverse(x.1));

    sorted
        .into_iter()
        .take(5)
        .map(|(name, count)| {
            let desc = tool_description(&name).to_string();
            ToolUsageSummary {
                tool_name: name,
                percentage: (count as f32 / total as f32) * 100.0,
                call_count: count,
                description: desc,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Network summarization
// ---------------------------------------------------------------------------

fn summarize_network(events: &[AuditEvent]) -> NetworkSummaryType {
    let network_events: Vec<&AuditEvent> = events
        .iter()
        .filter(|e| is_network_event(e))
        .collect();

    if network_events.is_empty() {
        return NetworkSummaryType::Never;
    }

    let mut host_counts: HashMap<String, u64> = HashMap::new();
    for event in &network_events {
        let host = event
            .resource
            .as_deref()
            .unwrap_or("unknown");
        *host_counts.entry(host.to_string()).or_insert(0) += 1;
    }

    let total_connections = network_events.len() as u64;

    if total_connections >= 3 {
        let mut hosts: Vec<String> = host_counts.keys().cloned().collect();
        hosts.sort();
        hosts.truncate(10);
        NetworkSummaryType::Regular {
            hosts,
            total_connections,
        }
    } else {
        let last = network_events.last().unwrap();
        NetworkSummaryType::Rare {
            last_connection: last.timestamp.clone(),
            host: last.resource.clone().unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

fn is_network_event(event: &AuditEvent) -> bool {
    matches!(
        event.event_type.as_str(),
        "connect" | "network" | "http" | "fetch"
    ) || matches!(
        event.action.as_str(),
        "connect" | "fetch" | "http_request"
    )
}

// ---------------------------------------------------------------------------
// Activity pattern analysis
// ---------------------------------------------------------------------------

fn summarize_activity(events: &[AuditEvent]) -> ActivityPattern {
    let now = Utc::now();
    let seven_days_ago = now - Duration::days(7);
    let twenty_four_hours_ago = now - Duration::hours(24);

    let mut recent_7d: Vec<&AuditEvent> = Vec::new();
    let mut hourly_buckets: [u32; 24] = [0; 24];

    for event in events {
        if let Ok(ts) = event.timestamp.parse::<DateTime<Utc>>() {
            if ts >= seven_days_ago {
                recent_7d.push(event);
            }
            if ts >= twenty_four_hours_ago {
                let hour = ts.hour() as usize;
                hourly_buckets[hour] += 1;
            }
        }
    }

    let total_hours = 7.0 * 24.0_f32;
    let avg_actions_per_hour = if total_hours > 0.0 {
        recent_7d.len() as f32 / total_hours
    } else {
        0.0
    };

    let hourly_data: Vec<f32> = hourly_buckets.iter().map(|&c| c as f32).collect();

    let peak_period = compute_peak_period(&hourly_buckets);

    // Check for unusual spikes: compare yesterday's total to the 7-day average.
    let unusual_note = detect_unusual_activity(events, avg_actions_per_hour);

    ActivityPattern {
        avg_actions_per_hour,
        hourly_data,
        peak_period,
        unusual_note,
    }
}

fn compute_peak_period(hourly: &[u32; 24]) -> String {
    if hourly.iter().all(|&c| c == 0) {
        return "No recent activity".to_string();
    }

    // Find the 3-hour window with the highest sum.
    let mut best_start = 0;
    let mut best_sum = 0u32;

    for start in 0..24 {
        let sum: u32 = (0..3).map(|offset| hourly[(start + offset) % 24]).sum();
        if sum > best_sum {
            best_sum = sum;
            best_start = start;
        }
    }

    let end = (best_start + 3) % 24;
    format!(
        "Most active between {}–{}",
        format_hour(best_start),
        format_hour(end)
    )
}

fn format_hour(h: usize) -> String {
    match h {
        0 => "12am".to_string(),
        1..=11 => format!("{}am", h),
        12 => "12pm".to_string(),
        _ => format!("{}pm", h - 12),
    }
}

fn detect_unusual_activity(events: &[AuditEvent], avg_per_hour: f32) -> Option<String> {
    if avg_per_hour < 0.01 {
        return None;
    }

    let now = Utc::now();
    let yesterday_start = now - Duration::hours(48);
    let yesterday_end = now - Duration::hours(24);

    let yesterday_count = events
        .iter()
        .filter(|e| {
            e.timestamp
                .parse::<DateTime<Utc>>()
                .map(|ts| ts >= yesterday_start && ts < yesterday_end)
                .unwrap_or(false)
        })
        .count();

    let yesterday_rate = yesterday_count as f32 / 24.0;
    let ratio = yesterday_rate / avg_per_hour;

    if ratio >= 3.0 {
        Some(format!(
            "Activity rate was {:.0}x normal yesterday",
            ratio
        ))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Learning status
// ---------------------------------------------------------------------------

fn build_learning_status(profile: &Option<ServerProfileSummary>) -> LearningStatusInfo {
    match profile {
        Some(p) => {
            let progress = (p.total_calls as f32 / LEARNING_EVENT_THRESHOLD as f32).min(1.0);
            let status = if p.status == "learning" {
                "learning"
            } else {
                "active"
            };
            let events_needed = if progress < 1.0 {
                LEARNING_EVENT_THRESHOLD as u32 - p.total_calls as u32
            } else {
                0
            };
            LearningStatusInfo {
                status: status.to_string(),
                progress,
                events_needed,
            }
        }
        None => LearningStatusInfo {
            status: "learning".to_string(),
            progress: 0.0,
            events_needed: LEARNING_EVENT_THRESHOLD as u32,
        },
    }
}

// ---------------------------------------------------------------------------
// Trust recommendation
// ---------------------------------------------------------------------------

fn compute_trust_recommendation(
    events: &[AuditEvent],
    profile: &Option<ServerProfileSummary>,
) -> String {
    // Check for health warnings via anomaly score.
    if let Some(p) = profile {
        if p.anomaly_score >= 0.7 {
            return "restricted".to_string();
        }
    }

    let has_shell = events.iter().any(|e| {
        e.action == "execute_command"
            || e.action == "run_command"
            || e.event_type == "exec"
    });

    let has_network = events.iter().any(|e| is_network_event(e));

    let unique_dirs: std::collections::HashSet<String> = events
        .iter()
        .filter_map(|e| e.resource.as_ref().map(|r| top_directory(r, 1)))
        .collect();

    let broad_access = unique_dirs.len() > 10;

    if has_network || broad_access {
        return "cautious".to_string();
    }

    if has_shell {
        return "standard".to_string();
    }

    // Profile is new or unknown.
    if profile.is_none() || profile.as_ref().map(|p| p.total_calls < 10).unwrap_or(false) {
        return "cautious".to_string();
    }

    // Mostly reads files in a focused directory set.
    "trusted".to_string()
}

// ---------------------------------------------------------------------------
// Notable observations
// ---------------------------------------------------------------------------

fn generate_observations(
    events: &[AuditEvent],
    profile: &Option<ServerProfileSummary>,
) -> Vec<String> {
    let mut observations: Vec<String> = Vec::new();

    // Unique directories accessed.
    let unique_dirs: std::collections::HashSet<String> = events
        .iter()
        .filter_map(|e| e.resource.as_ref().map(|r| top_directory(r, 2)))
        .collect();

    if unique_dirs.len() > 20 {
        observations.push(format!(
            "This tool has accessed {} different directories — that's broader than typical file servers.",
            unique_dirs.len()
        ));
    }

    // Network usage.
    let network_count = events.iter().filter(|e| is_network_event(e)).count();
    if network_count == 0 && !events.is_empty() {
        observations.push("This tool has never tried to access the internet.".to_string());
    }

    // Consistency check from profile.
    if let Some(p) = profile {
        if p.anomaly_score < 0.1 && p.total_calls > 100 {
            observations.push(
                "This tool's behavior has been completely consistent.".to_string(),
            );
        }
        if p.anomaly_score >= 0.7 {
            observations.push(
                "Unusual patterns have been detected in this tool's recent activity.".to_string(),
            );
        }
    }

    // Shell usage trend.
    let shell_count = events
        .iter()
        .filter(|e| {
            e.action == "execute_command"
                || e.action == "run_command"
                || e.event_type == "exec"
        })
        .count();
    if shell_count > 0 {
        observations.push(format!(
            "This tool has executed {} shell commands.",
            shell_count
        ));
    }

    // Keep at most 3.
    observations.truncate(3);
    observations
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AuditEvent;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn make_event(
        server: &str,
        tool: Option<&str>,
        action: &str,
        event_type: &str,
        resource: Option<&str>,
        timestamp: &str,
    ) -> AuditEvent {
        AuditEvent {
            id: format!("test-{}", TEST_ID.fetch_add(1, Ordering::Relaxed)),
            timestamp: timestamp.to_string(),
            event_type: event_type.to_string(),
            server_name: server.to_string(),
            tool_name: tool.map(|s| s.to_string()),
            action: action.to_string(),
            decision: "allow".to_string(),
            risk_level: "info".to_string(),
            details: String::new(),
            resource: resource.map(|s| s.to_string()),
        }
    }

    fn make_profile(
        server: &str,
        total_calls: u64,
        status: &str,
        anomaly_score: f64,
    ) -> ServerProfileSummary {
        ServerProfileSummary {
            server_name: server.to_string(),
            tools_count: 5,
            total_calls,
            anomaly_score,
            status: status.to_string(),
            last_activity: "2026-02-25T10:00:00Z".to_string(),
        }
    }

    // -- Territory tests --

    #[test]
    fn test_territory_summarization() {
        let events = vec![
            make_event("fs", Some("read_file"), "read", "proxy", Some("/home/user/project/src/main.rs"), "2026-02-25T10:00:00Z"),
            make_event("fs", Some("read_file"), "read", "proxy", Some("/home/user/project/src/lib.rs"), "2026-02-25T10:01:00Z"),
            make_event("fs", Some("read_file"), "read", "proxy", Some("/home/user/project/tests/test.rs"), "2026-02-25T10:02:00Z"),
            make_event("fs", Some("write_file"), "write", "proxy", Some("/tmp/output.txt"), "2026-02-25T10:03:00Z"),
        ];

        let territory = summarize_territory(&events);
        assert!(!territory.is_empty());
        // The top directory should be /home/user based on 2-level grouping.
        assert_eq!(territory[0].path, "/home/user");
        assert_eq!(territory[0].access_count, 3);
    }

    #[test]
    fn test_territory_empty_events() {
        let territory = summarize_territory(&[]);
        assert!(territory.is_empty());
    }

    #[test]
    fn test_territory_other_bucket() {
        // 10 events in /a/b, 1 each in /c/d, /e/f, /g/h, /i/j = 14 total
        // Top 3 covers /a/b, /c/d, /e/f. Remainder is 2/14 = 14% > 5%.
        let mut events = Vec::new();
        for _ in 0..10 {
            events.push(make_event("fs", None, "read", "proxy", Some("/a/b/file.txt"), "2026-02-25T10:00:00Z"));
        }
        events.push(make_event("fs", None, "read", "proxy", Some("/c/d/file.txt"), "2026-02-25T10:01:00Z"));
        events.push(make_event("fs", None, "read", "proxy", Some("/e/f/file.txt"), "2026-02-25T10:02:00Z"));
        events.push(make_event("fs", None, "read", "proxy", Some("/g/h/file.txt"), "2026-02-25T10:03:00Z"));
        events.push(make_event("fs", None, "read", "proxy", Some("/i/j/file.txt"), "2026-02-25T10:04:00Z"));

        let territory = summarize_territory(&events);
        assert!(territory.iter().any(|d| d.path == "(other)"));
    }

    // -- Tool usage tests --

    #[test]
    fn test_tool_usage_summarization() {
        let events = vec![
            make_event("fs", Some("read_file"), "read", "proxy", None, "2026-02-25T10:00:00Z"),
            make_event("fs", Some("read_file"), "read", "proxy", None, "2026-02-25T10:01:00Z"),
            make_event("fs", Some("write_file"), "write", "proxy", None, "2026-02-25T10:02:00Z"),
            make_event("fs", Some("execute_command"), "exec", "proxy", None, "2026-02-25T10:03:00Z"),
        ];

        let tools = summarize_tools(&events);
        assert_eq!(tools.len(), 3);
        assert_eq!(tools[0].tool_name, "read_file");
        assert_eq!(tools[0].call_count, 2);
        assert_eq!(tools[0].description, "Reads file contents");
        assert!((tools[0].percentage - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_tool_usage_empty() {
        let tools = summarize_tools(&[]);
        assert!(tools.is_empty());
    }

    #[test]
    fn test_tool_usage_top5_limit() {
        let tool_names = ["a", "b", "c", "d", "e", "f", "g"];
        let events: Vec<AuditEvent> = tool_names
            .iter()
            .map(|t| make_event("fs", Some(t), "call", "proxy", None, "2026-02-25T10:00:00Z"))
            .collect();

        let tools = summarize_tools(&events);
        assert_eq!(tools.len(), 5);
    }

    // -- Network summary tests --

    #[test]
    fn test_network_never() {
        let events = vec![
            make_event("fs", Some("read_file"), "read", "proxy", None, "2026-02-25T10:00:00Z"),
        ];
        let summary = summarize_network(&events);
        assert!(matches!(summary, NetworkSummaryType::Never));
    }

    #[test]
    fn test_network_regular() {
        let events = vec![
            make_event("fs", None, "connect", "connect", Some("api.example.com"), "2026-02-25T10:00:00Z"),
            make_event("fs", None, "connect", "connect", Some("cdn.example.com"), "2026-02-25T10:01:00Z"),
            make_event("fs", None, "connect", "connect", Some("api.example.com"), "2026-02-25T10:02:00Z"),
        ];
        let summary = summarize_network(&events);
        match summary {
            NetworkSummaryType::Regular { hosts, total_connections } => {
                assert_eq!(total_connections, 3);
                assert!(hosts.contains(&"api.example.com".to_string()));
                assert!(hosts.contains(&"cdn.example.com".to_string()));
            }
            _ => panic!("Expected Regular network summary"),
        }
    }

    #[test]
    fn test_network_rare() {
        let events = vec![
            make_event("fs", None, "fetch", "fetch", Some("once.example.com"), "2026-02-25T10:00:00Z"),
        ];
        let summary = summarize_network(&events);
        match summary {
            NetworkSummaryType::Rare { host, .. } => {
                assert_eq!(host, "once.example.com");
            }
            _ => panic!("Expected Rare network summary"),
        }
    }

    // -- Activity pattern tests --

    #[test]
    fn test_activity_pattern_basic() {
        let now = Utc::now();
        let events: Vec<AuditEvent> = (0..48)
            .map(|i| {
                let ts = now - Duration::hours(i);
                make_event("fs", Some("read_file"), "read", "proxy", None, &ts.to_rfc3339())
            })
            .collect();

        let pattern = summarize_activity(&events);
        assert!(pattern.avg_actions_per_hour > 0.0);
        assert_eq!(pattern.hourly_data.len(), 24);
        assert!(!pattern.peak_period.is_empty());
    }

    #[test]
    fn test_activity_pattern_empty() {
        let pattern = summarize_activity(&[]);
        assert_eq!(pattern.avg_actions_per_hour, 0.0);
        assert_eq!(pattern.hourly_data.len(), 24);
        assert_eq!(pattern.peak_period, "No recent activity");
    }

    // -- Trust recommendation tests --

    #[test]
    fn test_trust_recommendation_restricted_for_high_anomaly() {
        let profile = Some(make_profile("fs", 200, "active", 0.8));
        let trust = compute_trust_recommendation(&[], &profile);
        assert_eq!(trust, "restricted");
    }

    #[test]
    fn test_trust_recommendation_cautious_for_network() {
        let events = vec![
            make_event("fs", None, "connect", "connect", Some("example.com"), "2026-02-25T10:00:00Z"),
        ];
        let profile = Some(make_profile("fs", 200, "active", 0.1));
        let trust = compute_trust_recommendation(&events, &profile);
        assert_eq!(trust, "cautious");
    }

    #[test]
    fn test_trust_recommendation_standard_for_shell() {
        let events = vec![
            make_event("fs", None, "execute_command", "exec", None, "2026-02-25T10:00:00Z"),
        ];
        let profile = Some(make_profile("fs", 200, "active", 0.1));
        let trust = compute_trust_recommendation(&events, &profile);
        assert_eq!(trust, "standard");
    }

    #[test]
    fn test_trust_recommendation_cautious_for_new_profile() {
        let trust = compute_trust_recommendation(&[], &None);
        assert_eq!(trust, "cautious");
    }

    #[test]
    fn test_trust_recommendation_trusted_for_calm_profile() {
        let events = vec![
            make_event("fs", Some("read_file"), "read", "proxy", Some("/project/src/main.rs"), "2026-02-25T10:00:00Z"),
        ];
        let profile = Some(make_profile("fs", 200, "active", 0.05));
        let trust = compute_trust_recommendation(&events, &profile);
        assert_eq!(trust, "trusted");
    }

    // -- Notable observations tests --

    #[test]
    fn test_observations_broad_access() {
        let mut events = Vec::new();
        for i in 0..25 {
            events.push(make_event(
                "fs",
                Some("read_file"),
                "read",
                "proxy",
                Some(&format!("/dir{}/sub/file.txt", i)),
                "2026-02-25T10:00:00Z",
            ));
        }
        let obs = generate_observations(&events, &None);
        assert!(obs.iter().any(|o| o.contains("different directories")));
    }

    #[test]
    fn test_observations_no_network() {
        let events = vec![
            make_event("fs", Some("read_file"), "read", "proxy", None, "2026-02-25T10:00:00Z"),
        ];
        let obs = generate_observations(&events, &None);
        assert!(obs.iter().any(|o| o.contains("never tried to access the internet")));
    }

    #[test]
    fn test_observations_consistent() {
        let profile = Some(make_profile("fs", 200, "active", 0.05));
        let obs = generate_observations(&[], &profile);
        assert!(obs.iter().any(|o| o.contains("completely consistent")));
    }

    #[test]
    fn test_observations_max_three() {
        // Generate events that trigger many observations.
        let mut events = Vec::new();
        for i in 0..25 {
            events.push(make_event(
                "fs",
                Some("read_file"),
                "read",
                "proxy",
                Some(&format!("/dir{}/sub/file.txt", i)),
                "2026-02-25T10:00:00Z",
            ));
        }
        events.push(make_event("fs", None, "execute_command", "exec", None, "2026-02-25T10:00:00Z"));

        let profile = Some(make_profile("fs", 200, "active", 0.05));
        let obs = generate_observations(&events, &profile);
        assert!(obs.len() <= 3);
    }

    // -- Helper tests --

    #[test]
    fn test_top_directory() {
        assert_eq!(top_directory("/home/user/project/src/main.rs", 2), "/home/user");
        assert_eq!(top_directory("/tmp/output.txt", 2), "/tmp/output.txt");
        assert_eq!(top_directory("/a/b/c/d/e", 2), "/a/b");
        assert_eq!(top_directory("relative/path", 2), "/relative/path");
    }

    #[test]
    fn test_format_hour() {
        assert_eq!(format_hour(0), "12am");
        assert_eq!(format_hour(9), "9am");
        assert_eq!(format_hour(12), "12pm");
        assert_eq!(format_hour(15), "3pm");
        assert_eq!(format_hour(23), "11pm");
    }

    #[test]
    fn test_learning_status_learning() {
        let profile = Some(make_profile("fs", 50, "learning", 0.0));
        let status = build_learning_status(&profile);
        assert_eq!(status.status, "learning");
        assert!((status.progress - 0.5).abs() < 0.01);
        assert_eq!(status.events_needed, 50);
    }

    #[test]
    fn test_learning_status_active() {
        let profile = Some(make_profile("fs", 200, "active", 0.0));
        let status = build_learning_status(&profile);
        assert_eq!(status.status, "active");
        assert!((status.progress - 1.0).abs() < 0.01);
        assert_eq!(status.events_needed, 0);
    }

    #[test]
    fn test_learning_status_no_profile() {
        let status = build_learning_status(&None);
        assert_eq!(status.status, "learning");
        assert_eq!(status.progress, 0.0);
        assert_eq!(status.events_needed, 100);
    }

    #[test]
    fn test_tool_description_known() {
        assert_eq!(tool_description("read_file"), "Reads file contents");
        assert_eq!(tool_description("execute_command"), "Runs shell commands");
        assert_eq!(tool_description("fetch"), "Makes HTTP requests");
    }

    #[test]
    fn test_tool_description_unknown() {
        assert_eq!(tool_description("my_custom_tool"), "Custom tool operation");
    }
}
