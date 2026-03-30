use serde::{Deserialize, Serialize};

use crate::state::AuditEvent;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub mcp_event_id: String,
    pub correlated_events: Vec<CorrelatedEvent>,
    pub correlation_confidence: f32,
    pub uncorrelated_events: Vec<UncorrelatedEvent>,
    pub coverage: CoverageAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub event_id: String,
    pub timestamp: String,
    pub description: String,
    pub match_confidence: f32,
    pub match_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncorrelatedEvent {
    pub event_id: String,
    pub timestamp: String,
    pub description: String,
    pub concern_level: String, // "low", "medium", "high"
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAssessment {
    pub mcp_events_with_match: u32,
    pub mcp_events_without_match: u32,
    pub uncorrelated_count: u32,
    pub coverage_percent: f32,
    pub assessment: String, // "Good coverage" or "Gap detected"
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse an ISO-8601 timestamp to epoch milliseconds. Returns `None` for
/// unparsable strings.
fn timestamp_ms(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

/// True when an event looks like it came through the MCP protocol channel.
fn is_mcp_event(event: &AuditEvent) -> bool {
    let et = event.event_type.to_lowercase();
    et.contains("proxy") || et.contains("mcp") || et == "tools/call" || et == "resources/read"
}

/// True when an event looks like an OS-level / system observation rather than
/// an MCP protocol message.
fn is_os_event(event: &AuditEvent) -> bool {
    let et = event.event_type.to_lowercase();
    et.contains("system") || et.contains("os") || et.contains("network") || et.contains("file")
}

/// Compute confidence [0.0, 1.0] based on time gap and type compatibility.
fn compute_confidence(gap_ms: i64, same_server: bool, type_compatible: bool) -> f32 {
    // Time component: closer = better. Linear decay over 5 seconds.
    let time_factor = 1.0 - (gap_ms as f32 / 5000.0).min(1.0);

    let server_factor: f32 = if same_server { 1.0 } else { 0.6 };
    let type_factor: f32 = if type_compatible { 1.0 } else { 0.5 };

    (time_factor * server_factor * type_factor).clamp(0.0, 1.0)
}

/// Build a human-friendly description for a correlated event.
fn event_description(event: &AuditEvent) -> String {
    if let Some(ref tool) = event.tool_name {
        format!("{}: {}", tool, event.action)
    } else {
        event.action.clone()
    }
}

/// Determine concern level for an uncorrelated OS event.
fn concern_for_uncorrelated(event: &AuditEvent) -> &'static str {
    match event.risk_level.as_str() {
        "critical" | "high" => "high",
        "medium" => "medium",
        _ => "low",
    }
}

/// Produce an explanation string for an uncorrelated event.
fn uncorrelated_explanation(event: &AuditEvent) -> String {
    format!(
        "OS-level activity from {} ({}) with no matching MCP request in the time window",
        event.server_name, event.action
    )
}

/// Check whether two event types are "compatible" for correlation (e.g. both
/// involve the same server or tool category).
fn types_compatible(a: &AuditEvent, b: &AuditEvent) -> bool {
    // Same tool name is a strong signal.
    if a.tool_name.is_some() && a.tool_name == b.tool_name {
        return true;
    }
    // Same action keyword.
    if !a.action.is_empty() && a.action == b.action {
        return true;
    }
    // Resource overlap.
    if let (Some(ra), Some(rb)) = (a.resource.as_deref(), b.resource.as_deref()) {
        if !ra.is_empty() && !rb.is_empty() && (ra.contains(rb) || rb.contains(ra)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Correlate a single MCP event against all known events.
///
/// - Same server within +/- 2 s  -> tight correlation window
/// - Different sources within +/- 5 s -> OS-level correlation
/// - Uncorrelated: OS events near the target that don't match any MCP event
pub fn correlate_event(event_id: &str, all_events: &[AuditEvent]) -> CorrelationResult {
    let target = match all_events.iter().find(|e| e.id == event_id) {
        Some(t) => t,
        None => {
            return CorrelationResult {
                mcp_event_id: event_id.to_string(),
                correlated_events: vec![],
                correlation_confidence: 0.0,
                uncorrelated_events: vec![],
                coverage: CoverageAssessment {
                    mcp_events_with_match: 0,
                    mcp_events_without_match: 0,
                    uncorrelated_count: 0,
                    coverage_percent: 0.0,
                    assessment: "Event not found".to_string(),
                },
            };
        }
    };

    let target_ms = match timestamp_ms(&target.timestamp) {
        Some(ms) => ms,
        None => {
            return CorrelationResult {
                mcp_event_id: event_id.to_string(),
                correlated_events: vec![],
                correlation_confidence: 0.0,
                uncorrelated_events: vec![],
                coverage: CoverageAssessment {
                    mcp_events_with_match: 0,
                    mcp_events_without_match: 0,
                    uncorrelated_count: 0,
                    coverage_percent: 0.0,
                    assessment: "Could not parse event timestamp".to_string(),
                },
            };
        }
    };

    let mut correlated: Vec<CorrelatedEvent> = Vec::new();
    let mut uncorrelated: Vec<UncorrelatedEvent> = Vec::new();
    let mut matched_ids: Vec<String> = Vec::new();

    for other in all_events {
        if other.id == event_id {
            continue;
        }
        let other_ms = match timestamp_ms(&other.timestamp) {
            Some(ms) => ms,
            None => continue,
        };

        let gap_ms = (other_ms - target_ms).unsigned_abs() as i64;
        let same_server = other.server_name == target.server_name;

        // Tight window for same-server events
        if same_server && gap_ms <= 2000 {
            let compat = types_compatible(target, other);
            let confidence = compute_confidence(gap_ms, true, compat);
            let reason = if compat {
                format!("Same server, matching activity within {}ms", gap_ms)
            } else {
                format!("Same server, within {}ms", gap_ms)
            };
            correlated.push(CorrelatedEvent {
                event_id: other.id.clone(),
                timestamp: other.timestamp.clone(),
                description: event_description(other),
                match_confidence: confidence,
                match_reason: reason,
            });
            matched_ids.push(other.id.clone());
            continue;
        }

        // Wider window for cross-source correlation
        if gap_ms <= 5000 && (is_os_event(other) || !same_server) {
            let compat = types_compatible(target, other);
            let confidence = compute_confidence(gap_ms, same_server, compat);
            if confidence >= 0.2 {
                let reason = if same_server {
                    format!("OS activity on same server within {}ms", gap_ms)
                } else {
                    format!("Cross-source activity within {}ms", gap_ms)
                };
                correlated.push(CorrelatedEvent {
                    event_id: other.id.clone(),
                    timestamp: other.timestamp.clone(),
                    description: event_description(other),
                    match_confidence: confidence,
                    match_reason: reason,
                });
                matched_ids.push(other.id.clone());
            }
        }
    }

    // Identify uncorrelated OS events within the 5-second window
    for other in all_events {
        if other.id == event_id || matched_ids.contains(&other.id) {
            continue;
        }
        if !is_os_event(other) {
            continue;
        }
        let other_ms = match timestamp_ms(&other.timestamp) {
            Some(ms) => ms,
            None => continue,
        };
        let gap_ms = (other_ms - target_ms).unsigned_abs() as i64;
        if gap_ms <= 5000 {
            uncorrelated.push(UncorrelatedEvent {
                event_id: other.id.clone(),
                timestamp: other.timestamp.clone(),
                description: event_description(other),
                concern_level: concern_for_uncorrelated(other).to_string(),
                explanation: uncorrelated_explanation(other),
            });
        }
    }

    // Sort by confidence descending
    correlated.sort_by(|a, b| b.match_confidence.partial_cmp(&a.match_confidence).unwrap_or(std::cmp::Ordering::Equal));

    let overall_confidence = if correlated.is_empty() {
        0.0
    } else {
        correlated.iter().map(|c| c.match_confidence).sum::<f32>() / correlated.len() as f32
    };

    let coverage = compute_coverage_around(target, all_events);

    CorrelationResult {
        mcp_event_id: event_id.to_string(),
        correlated_events: correlated,
        correlation_confidence: overall_confidence,
        uncorrelated_events: uncorrelated,
        coverage,
    }
}

/// Compute coverage for all MCP events in the vicinity of a target event.
fn compute_coverage_around(target: &AuditEvent, all_events: &[AuditEvent]) -> CoverageAssessment {
    let target_ms = match timestamp_ms(&target.timestamp) {
        Some(ms) => ms,
        None => {
            return CoverageAssessment {
                mcp_events_with_match: 0,
                mcp_events_without_match: 0,
                uncorrelated_count: 0,
                coverage_percent: 0.0,
                assessment: "Could not compute coverage".to_string(),
            };
        }
    };

    // Look at events within +/- 30 seconds for coverage assessment
    let window_ms = 30_000i64;
    let nearby: Vec<&AuditEvent> = all_events
        .iter()
        .filter(|e| {
            if let Some(ms) = timestamp_ms(&e.timestamp) {
                (ms - target_ms).unsigned_abs() as i64 <= window_ms
            } else {
                false
            }
        })
        .collect();

    let mcp_events: Vec<&&AuditEvent> = nearby.iter().filter(|e| is_mcp_event(e)).collect();
    let os_events: Vec<&&AuditEvent> = nearby.iter().filter(|e| is_os_event(e)).collect();

    let mut with_match = 0u32;
    let mut without_match = 0u32;
    let mut matched_os_ids: Vec<String> = Vec::new();

    for mcp in &mcp_events {
        let mcp_ms = timestamp_ms(&mcp.timestamp).unwrap_or(0);
        let has_match = os_events.iter().any(|os| {
            let os_ms = timestamp_ms(&os.timestamp).unwrap_or(0);
            let gap = (os_ms - mcp_ms).unsigned_abs() as i64;
            if gap <= 5000 {
                matched_os_ids.push(os.id.clone());
                true
            } else {
                false
            }
        });
        if has_match {
            with_match += 1;
        } else {
            without_match += 1;
        }
    }

    let unmatched_os = os_events
        .iter()
        .filter(|os| !matched_os_ids.contains(&os.id))
        .count() as u32;

    let total_mcp = with_match + without_match;
    let percent = if total_mcp > 0 {
        (with_match as f32 / total_mcp as f32) * 100.0
    } else {
        100.0 // no MCP events = vacuously covered
    };

    let assessment = if percent >= 70.0 {
        "Good coverage -- I can see what this tool is doing through the MCP channel".to_string()
    } else {
        "Gap detected -- this tool is doing things I can't fully see through the MCP channel"
            .to_string()
    };

    CoverageAssessment {
        mcp_events_with_match: with_match,
        mcp_events_without_match: without_match,
        uncorrelated_count: unmatched_os,
        coverage_percent: percent,
        assessment,
    }
}

/// Get coverage assessment for a specific server over a time window.
pub fn get_coverage_for_server(
    server_name: &str,
    events: &[AuditEvent],
    hours: u32,
) -> CoverageAssessment {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let window_ms = hours as i64 * 3_600_000;
    let cutoff = now_ms - window_ms;

    let server_events: Vec<&AuditEvent> = events
        .iter()
        .filter(|e| {
            e.server_name == server_name
                && timestamp_ms(&e.timestamp).map_or(false, |ms| ms >= cutoff)
        })
        .collect();

    let mcp_events: Vec<&&AuditEvent> = server_events.iter().filter(|e| is_mcp_event(e)).collect();
    let os_events: Vec<&&AuditEvent> = server_events.iter().filter(|e| is_os_event(e)).collect();

    let mut with_match = 0u32;
    let mut without_match = 0u32;
    let mut matched_os_ids: Vec<String> = Vec::new();

    for mcp in &mcp_events {
        let mcp_ms = timestamp_ms(&mcp.timestamp).unwrap_or(0);
        let has_match = os_events.iter().any(|os| {
            let os_ms = timestamp_ms(&os.timestamp).unwrap_or(0);
            let gap = (os_ms - mcp_ms).unsigned_abs() as i64;
            if gap <= 5000 {
                matched_os_ids.push(os.id.clone());
                true
            } else {
                false
            }
        });
        if has_match {
            with_match += 1;
        } else {
            without_match += 1;
        }
    }

    let unmatched_os = os_events
        .iter()
        .filter(|os| !matched_os_ids.contains(&os.id))
        .count() as u32;

    let total_mcp = with_match + without_match;
    let percent = if total_mcp > 0 {
        (with_match as f32 / total_mcp as f32) * 100.0
    } else if os_events.is_empty() {
        100.0
    } else {
        0.0 // only OS events, no MCP -- poor coverage
    };

    let assessment = if percent >= 70.0 {
        format!(
            "Good coverage -- I can see most of what {} is doing",
            server_name
        )
    } else {
        format!(
            "Gap detected -- {} is doing things I can't fully see through the MCP channel",
            server_name
        )
    };

    CoverageAssessment {
        mcp_events_with_match: with_match,
        mcp_events_without_match: without_match,
        uncorrelated_count: unmatched_os,
        coverage_percent: percent,
        assessment,
    }
}
