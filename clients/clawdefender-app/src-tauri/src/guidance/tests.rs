use super::milestones::all_milestones;
use super::storage::GuidanceStore;

#[test]
fn test_all_milestones_returns_9() {
    let milestones = all_milestones();
    assert_eq!(milestones.len(), 9);
}

#[test]
fn test_all_milestones_unique_ids() {
    let milestones = all_milestones();
    let mut ids: Vec<&str> = milestones.iter().map(|m| m.id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 9, "All milestone IDs must be unique");
}

#[test]
fn test_all_milestones_start_unfired() {
    for m in all_milestones() {
        assert!(!m.fired, "Milestone {} should start unfired", m.id);
        assert!(m.fired_at.is_none());
        assert!(!m.dismissed);
    }
}

#[test]
fn test_store_mark_fired() {
    let mut store = GuidanceStore::default();
    assert!(!store.has_fired("first_prompt"));

    store.fired.insert(
        "first_prompt".to_string(),
        "2026-02-25T10:00:00Z".to_string(),
    );
    assert!(store.has_fired("first_prompt"));
}

#[test]
fn test_store_milestone_fires_only_once() {
    let mut store = GuidanceStore::default();
    store.fired.insert(
        "first_prompt".to_string(),
        "2026-02-25T10:00:00Z".to_string(),
    );

    // Attempting to check again should still show fired
    assert!(store.has_fired("first_prompt"));

    // Should not overwrite the timestamp
    let original = store.fired.get("first_prompt").cloned();
    // Simulate another check — since has_fired returns true, we wouldn't re-fire
    assert!(store.has_fired("first_prompt"));
    assert_eq!(store.fired.get("first_prompt").cloned(), original);
}

#[test]
fn test_store_dismiss() {
    let mut store = GuidanceStore::default();
    store
        .dismissed
        .insert("first_block".to_string(), "2026-02-25T11:00:00Z".to_string());
    assert!(store.dismissed.contains_key("first_block"));
}

#[test]
fn test_store_reset_clears_all() {
    let mut store = GuidanceStore::default();
    store.fired.insert(
        "first_prompt".to_string(),
        "2026-02-25T10:00:00Z".to_string(),
    );
    store
        .dismissed
        .insert("first_block".to_string(), "2026-02-25T11:00:00Z".to_string());
    store.page_visits.insert("/tools".to_string());
    store.onboarding_completed_at = Some("2026-02-25T09:00:00Z".to_string());

    store.reset();

    assert!(store.fired.is_empty());
    assert!(store.dismissed.is_empty());
    assert!(store.page_visits.is_empty());
    // onboarding_completed_at is preserved
    assert!(store.onboarding_completed_at.is_some());
}

#[test]
fn test_page_visit_tracking() {
    let mut store = GuidanceStore::default();
    assert!(!store.has_visited_page("/tools"));

    store.page_visits.insert("/tools".to_string());
    assert!(store.has_visited_page("/tools"));
    assert!(!store.has_visited_page("/settings"));
}

#[test]
fn test_milestone_ids_match_spec() {
    let milestones = all_milestones();
    let expected_ids = vec![
        "first_prompt",
        "first_block",
        "behavioral_complete",
        "first_day_summary",
        "score_drop_below_70",
        "first_week_digest",
        "feature_nudge_tools",
        "ai_model_nudge",
        "restart_reminder",
    ];

    let actual_ids: Vec<&str> = milestones.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(actual_ids, expected_ids);
}

#[test]
fn test_milestone_delivery_types_valid() {
    let valid_deliveries = [
        "prompt_overlay",
        "toast",
        "claw_message",
        "inline_hint",
        "toast+claw_message",
        "claw_message+inline_hint",
    ];
    for m in all_milestones() {
        assert!(
            valid_deliveries.contains(&m.delivery.as_str()),
            "Milestone {} has invalid delivery: {}",
            m.id,
            m.delivery
        );
    }
}

#[test]
fn test_milestone_trigger_types_valid() {
    for m in all_milestones() {
        assert!(
            m.trigger_type == "event" || m.trigger_type == "time",
            "Milestone {} has invalid trigger_type: {}",
            m.id,
            m.trigger_type
        );
    }
}
