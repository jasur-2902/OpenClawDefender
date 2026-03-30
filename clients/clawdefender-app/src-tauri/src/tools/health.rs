use serde::{Deserialize, Serialize};

use crate::state::{AppState, ReputationResult, ScanResult, ServerProfileSummary};

/// A health warning for a specific MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthWarning {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub recommended_action: String,
    pub action_type: String,
}

/// Generate health warnings for a server based on multiple data sources.
pub fn get_server_health(
    _server_name: &str,
    is_wrapped: bool,
    profile: Option<&ServerProfileSummary>,
    scan_result: Option<&ScanResult>,
    reputation: Option<&ReputationResult>,
) -> Vec<HealthWarning> {
    let mut warnings = Vec::new();

    // Not wrapped
    if !is_wrapped {
        warnings.push(HealthWarning {
            severity: "warning".to_string(),
            title: "Not protected".to_string(),
            description: "This tool is not protected by Claw yet. Its actions are not being monitored.".to_string(),
            recommended_action: "Protect now".to_string(),
            action_type: "wrap".to_string(),
        });
    }

    // Reputation match
    if let Some(rep) = reputation {
        if !rep.clean {
            let match_count = rep.matches.len();
            warnings.push(HealthWarning {
                severity: "critical".to_string(),
                title: "Blocklist match".to_string(),
                description: format!(
                    "This tool matches {} known threat{} in the blocklist.",
                    match_count,
                    if match_count == 1 { "" } else { "s" }
                ),
                recommended_action: "Review and restrict".to_string(),
                action_type: "restrict".to_string(),
            });
        }
    }

    // Scan findings
    if let Some(scan) = scan_result {
        if scan.critical_count > 0 {
            warnings.push(HealthWarning {
                severity: "critical".to_string(),
                title: "Critical scan findings".to_string(),
                description: format!(
                    "{} critical issue{} found in the last scan.",
                    scan.critical_count,
                    if scan.critical_count == 1 { "" } else { "s" }
                ),
                recommended_action: "View scan details".to_string(),
                action_type: "scan".to_string(),
            });
        } else if scan.high_count > 0 {
            warnings.push(HealthWarning {
                severity: "high".to_string(),
                title: "High-severity scan findings".to_string(),
                description: format!(
                    "{} high-severity issue{} found in the last scan.",
                    scan.high_count,
                    if scan.high_count == 1 { "" } else { "s" }
                ),
                recommended_action: "View scan details".to_string(),
                action_type: "scan".to_string(),
            });
        }
    } else if is_wrapped {
        // No scan ever run on a wrapped server
        warnings.push(HealthWarning {
            severity: "info".to_string(),
            title: "Not scanned yet".to_string(),
            description: "This tool has not been scanned yet. Run a scan to check for issues.".to_string(),
            recommended_action: "Scan now".to_string(),
            action_type: "scan".to_string(),
        });
    }

    // Behavioral profile age check
    if let Some(prof) = profile {
        if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&prof.last_activity) {
            let age = chrono::Utc::now().signed_duration_since(last);
            if age.num_days() >= 30 {
                warnings.push(HealthWarning {
                    severity: "info".to_string(),
                    title: "Inactive tool".to_string(),
                    description: format!(
                        "This tool has been inactive for {} days. Consider removing it if no longer needed.",
                        age.num_days()
                    ),
                    recommended_action: "Review".to_string(),
                    action_type: "remove".to_string(),
                });
            }
        }
    }

    warnings
}

/// Convenience wrapper that extracts data from AppState for a given server.
pub fn get_server_health_from_state(
    server_name: &str,
    is_wrapped: bool,
    _state: &AppState,
) -> Vec<HealthWarning> {
    // We don't have direct per-server scan results or reputation in state,
    // so we return what we can determine from in-memory data.
    // The full card assembler will pass richer data.
    get_server_health(server_name, is_wrapped, None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::*;

    #[test]
    fn test_unwrapped_server_warning() {
        let warnings = get_server_health("test", false, None, None, None);
        assert!(!warnings.is_empty());
        assert_eq!(warnings[0].severity, "warning");
        assert_eq!(warnings[0].action_type, "wrap");
    }

    #[test]
    fn test_wrapped_no_scan_warning() {
        let warnings = get_server_health("test", true, None, None, None);
        let scan_warning = warnings.iter().find(|w| w.action_type == "scan");
        assert!(scan_warning.is_some());
        assert_eq!(scan_warning.unwrap().severity, "info");
    }

    #[test]
    fn test_critical_scan_findings() {
        let scan = ScanResult {
            scan_id: "s1".to_string(),
            status: "completed".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: Some("2026-01-01T00:01:00Z".to_string()),
            modules: Vec::new(),
            total_findings: 3,
            critical_count: 2,
            high_count: 1,
            medium_count: 0,
            low_count: 0,
        };
        let warnings = get_server_health("test", true, None, Some(&scan), None);
        let critical = warnings.iter().find(|w| w.severity == "critical");
        assert!(critical.is_some());
        assert!(critical.unwrap().description.contains("2 critical"));
    }

    #[test]
    fn test_high_scan_findings() {
        let scan = ScanResult {
            scan_id: "s1".to_string(),
            status: "completed".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: Some("2026-01-01T00:01:00Z".to_string()),
            modules: Vec::new(),
            total_findings: 2,
            critical_count: 0,
            high_count: 2,
            medium_count: 0,
            low_count: 0,
        };
        let warnings = get_server_health("test", true, None, Some(&scan), None);
        let high = warnings.iter().find(|w| w.severity == "high");
        assert!(high.is_some());
    }

    #[test]
    fn test_blocklist_match_warning() {
        let rep = ReputationResult {
            server_name: "test".to_string(),
            clean: false,
            matches: vec![ReputationMatch {
                entry_id: "e1".to_string(),
                severity: "critical".to_string(),
                description: "Known malicious".to_string(),
            }],
        };
        let warnings = get_server_health("test", true, None, None, Some(&rep));
        let critical = warnings.iter().find(|w| w.severity == "critical");
        assert!(critical.is_some());
        assert_eq!(critical.unwrap().action_type, "restrict");
    }

    #[test]
    fn test_inactive_tool_warning() {
        let old_date = (chrono::Utc::now() - chrono::Duration::days(45)).to_rfc3339();
        let profile = ServerProfileSummary {
            server_name: "test".to_string(),
            tools_count: 3,
            total_calls: 50,
            anomaly_score: 0.1,
            status: "normal".to_string(),
            last_activity: old_date,
        };
        let warnings = get_server_health("test", true, Some(&profile), None, None);
        let inactive = warnings.iter().find(|w| w.title == "Inactive tool");
        assert!(inactive.is_some());
        assert!(inactive.unwrap().description.contains("45 days"));
    }

    #[test]
    fn test_healthy_wrapped_scanned_server() {
        let scan = ScanResult {
            scan_id: "s1".to_string(),
            status: "completed".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: Some("2026-01-01T00:01:00Z".to_string()),
            modules: Vec::new(),
            total_findings: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
        };
        let rep = ReputationResult {
            server_name: "test".to_string(),
            clean: true,
            matches: vec![],
        };
        let recent_activity = chrono::Utc::now().to_rfc3339();
        let profile = ServerProfileSummary {
            server_name: "test".to_string(),
            tools_count: 3,
            total_calls: 200,
            anomaly_score: 0.1,
            status: "normal".to_string(),
            last_activity: recent_activity,
        };
        let warnings =
            get_server_health("test", true, Some(&profile), Some(&scan), Some(&rep));
        // Should have no warnings for a healthy server
        assert!(warnings.is_empty());
    }
}
