use crate::state::AppState;

use super::milestones::{all_milestones, GuidanceMilestone};

/// Get the full guidance state: all 9 milestones with their current fired/dismissed status.
#[tauri::command]
pub fn get_guidance_state(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<GuidanceMilestone>, String> {
    let store = state
        .guidance_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    let milestones: Vec<GuidanceMilestone> = all_milestones()
        .into_iter()
        .map(|mut m| {
            if let Some(fired_at) = store.fired.get(&m.id) {
                m.fired = true;
                m.fired_at = Some(fired_at.clone());
            }
            if store.dismissed.contains_key(&m.id) {
                m.dismissed = true;
            }
            m
        })
        .collect();

    Ok(milestones)
}

/// Dismiss a guidance milestone so it never shows again.
#[tauri::command]
pub fn dismiss_guidance(
    state: tauri::State<'_, AppState>,
    milestone_id: String,
) -> Result<(), String> {
    let mut store = state
        .guidance_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    let now = chrono::Utc::now().to_rfc3339();
    store.mark_dismissed(&milestone_id, &now);
    Ok(())
}

/// Reset all guidance milestones to unfired state (for testing/development).
#[tauri::command]
pub fn reset_guidance(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut store = state
        .guidance_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    store.reset();
    Ok(())
}

/// Record that the user visited a page (used for feature nudge triggers).
#[tauri::command]
pub fn record_page_visit(
    state: tauri::State<'_, AppState>,
    page: String,
) -> Result<(), String> {
    let mut store = state
        .guidance_store
        .lock()
        .map_err(|e| format!("Lock error: {}", e))?;

    store.record_page_visit(&page);
    Ok(())
}
