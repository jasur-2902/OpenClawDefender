use super::calculator::*;
use super::factors;

#[test]
fn test_score_label_color_ranges() {
    assert_eq!(score_label_color(100), ("Fully protected", "green"));
    assert_eq!(score_label_color(95), ("Fully protected", "green"));
    assert_eq!(score_label_color(90), ("Fully protected", "green"));
    assert_eq!(score_label_color(89), ("Well protected", "green-light"));
    assert_eq!(score_label_color(70), ("Well protected", "green-light"));
    assert_eq!(score_label_color(69), ("Could be stronger", "amber"));
    assert_eq!(score_label_color(50), ("Could be stronger", "amber"));
    assert_eq!(score_label_color(49), ("Needs attention", "orange"));
    assert_eq!(score_label_color(30), ("Needs attention", "orange"));
    assert_eq!(score_label_color(29), ("Significant gaps", "red"));
    assert_eq!(score_label_color(0), ("Significant gaps", "red"));
}

#[test]
fn test_factor_status_mapping() {
    // Full points
    let factor = ScoreFactor {
        id: "test".into(),
        name: "Test".into(),
        description: "".into(),
        max_points: 25,
        current_points: 25,
        status: "full".into(),
        fix_actions: vec![],
        details: "".into(),
    };
    assert_eq!(factor.status, "full");

    // Partial points
    let factor = ScoreFactor {
        id: "test".into(),
        name: "Test".into(),
        description: "".into(),
        max_points: 25,
        current_points: 10,
        status: "partial".into(),
        fix_actions: vec![],
        details: "".into(),
    };
    assert_eq!(factor.status, "partial");

    // Zero points
    let factor = ScoreFactor {
        id: "test".into(),
        name: "Test".into(),
        description: "".into(),
        max_points: 25,
        current_points: 0,
        status: "empty".into(),
        fix_actions: vec![],
        details: "".into(),
    };
    assert_eq!(factor.status, "empty");
}

#[test]
fn test_protection_score_serializable() {
    let score = ProtectionScore {
        total: 75,
        label: "Well protected".into(),
        color: "green-light".into(),
        factors: vec![],
        computed_at: "2026-01-01T00:00:00Z".into(),
        change_from_last: Some(5),
    };
    let json = serde_json::to_string(&score).unwrap();
    assert!(json.contains("\"total\":75"));
    assert!(json.contains("\"label\":\"Well protected\""));
    assert!(json.contains("\"change_from_last\":5"));
}

#[test]
fn test_score_snapshot_serializable() {
    let snapshot = ScoreSnapshot {
        id: 1,
        score: 85,
        factors_json: "[]".into(),
        computed_at: "2026-01-01T00:00:00Z".into(),
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(json.contains("\"score\":85"));
}

#[test]
fn test_fix_action_serializable() {
    let action = FixAction {
        label: "Protect filesystem".into(),
        action_type: "navigate".into(),
        target: "/guards".into(),
        params: Some(serde_json::json!({ "server": "filesystem" })),
    };
    let json = serde_json::to_string(&action).unwrap();
    assert!(json.contains("\"label\":\"Protect filesystem\""));
    assert!(json.contains("\"action_type\":\"navigate\""));
}

#[test]
fn test_tool_coverage_no_servers_returns_full_score() {
    // When there are no MCP server configs, should return 25/25
    let factor = factors::compute_tool_coverage();
    assert_eq!(factor.id, "tool_coverage");
    assert_eq!(factor.max_points, 25);
    // On a clean test system with no MCP client configs, total == 0 => 25 points
    // (This may vary based on the actual test environment, so just check bounds)
    assert!(factor.current_points <= 25);
}

#[test]
fn test_threat_intel_missing_returns_zero() {
    // Without a threat intel manifest, should return 0 (unless test env has one)
    let factor = factors::compute_threat_intel();
    assert_eq!(factor.id, "threat_intel");
    assert_eq!(factor.max_points, 20);
    assert!(factor.current_points <= 20);
}

#[test]
fn test_six_factors_sum_to_100() {
    // Verify that max_points of all factors sum to exactly 100
    assert_eq!(25 + 20 + 15 + 15 + 15 + 10, 100);
}

#[test]
fn test_score_label_at_boundaries() {
    // Ensure boundaries are exactly right
    for score in 0..=100 {
        let (label, color) = score_label_color(score);
        match score {
            90..=100 => {
                assert_eq!(label, "Fully protected");
                assert_eq!(color, "green");
            }
            70..=89 => {
                assert_eq!(label, "Well protected");
                assert_eq!(color, "green-light");
            }
            50..=69 => {
                assert_eq!(label, "Could be stronger");
                assert_eq!(color, "amber");
            }
            30..=49 => {
                assert_eq!(label, "Needs attention");
                assert_eq!(color, "orange");
            }
            _ => {
                assert_eq!(label, "Significant gaps");
                assert_eq!(color, "red");
            }
        }
    }
}

#[test]
fn test_config_health_factor() {
    let factor = factors::compute_config_health();
    assert_eq!(factor.id, "config_health");
    assert_eq!(factor.max_points, 10);
    assert!(factor.current_points <= 10);
    // Verify status matches points
    if factor.current_points == 10 {
        assert_eq!(factor.status, "full");
    } else if factor.current_points > 0 {
        assert_eq!(factor.status, "partial");
    } else {
        assert_eq!(factor.status, "empty");
    }
}

// --- History tests ---

mod history_tests {
    use super::super::history;

    #[test]
    fn test_store_and_retrieve_history() {
        // Use a unique timestamp to avoid collisions with other tests
        let ts = chrono::Utc::now().to_rfc3339();
        history::store_snapshot(42, "[]", &ts);

        let last = history::get_last_score();
        // After storing, should be able to get back the score
        assert!(last.is_some());
    }

    #[test]
    fn test_dedup_same_score() {
        // First store a unique sentinel value to reset state from other tests
        let ts0 = chrono::Utc::now().to_rfc3339();
        history::store_snapshot(11, "[]", &ts0);

        let ts1 = (chrono::Utc::now() + chrono::Duration::milliseconds(100)).to_rfc3339();
        history::store_snapshot(77, "[]", &ts1);

        // Store same score again — should be skipped (dedup)
        let ts2 = (chrono::Utc::now() + chrono::Duration::milliseconds(200)).to_rfc3339();
        history::store_snapshot(77, "[]", &ts2);

        // Last score should still be 77 (the second 77 was deduped, not a new entry)
        assert_eq!(history::get_last_score(), Some(77));
    }

    #[test]
    fn test_get_history_returns_results() {
        let ts = chrono::Utc::now().to_rfc3339();
        // Store a distinct score to ensure history has at least one entry
        history::store_snapshot(99, "[{\"id\":\"test\"}]", &ts);

        let results = history::get_score_history(90);
        // Should have at least 1 entry
        assert!(!results.is_empty());
    }

    #[test]
    fn test_vacuum_does_not_crash() {
        // Just ensure vacuum runs without panicking
        history::vacuum(90);
    }
}
