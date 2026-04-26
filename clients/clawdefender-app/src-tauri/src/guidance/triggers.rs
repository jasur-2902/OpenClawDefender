use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

use super::milestones::{all_milestones, GuidanceMilestone};

/// Payload emitted to the frontend when a guidance milestone fires.
#[derive(Debug, Clone, Serialize)]
pub struct GuidanceEvent {
    pub milestone: GuidanceMilestone,
}

/// Check event-driven milestones. Called from event_stream when relevant events occur.
pub fn check_event_milestone(app: &AppHandle, milestone_id: &str) {
    let state = app.state::<AppState>();
    let mut store = state.guidance_store.lock().unwrap_or_else(|e| e.into_inner());

    if store.has_fired(milestone_id) {
        return;
    }

    let definitions = all_milestones();
    let Some(mut milestone) = definitions.into_iter().find(|m| m.id == milestone_id) else {
        return;
    };

    let now = Utc::now().to_rfc3339();
    store.mark_fired(milestone_id, &now);

    milestone.fired = true;
    milestone.fired_at = Some(now);

    emit_guidance(app, &milestone);
}

/// Check the score-drop milestone. Called when protection score changes.
pub fn check_score_drop(app: &AppHandle, new_score: u32) {
    if new_score >= 70 {
        return;
    }

    let state = app.state::<AppState>();
    let store = state.guidance_store.lock().unwrap_or_else(|e| e.into_inner());

    if store.has_fired("score_drop_below_70") {
        return;
    }
    drop(store);

    check_event_milestone(app, "score_drop_below_70");
}

/// Run time-based milestone checks. Called periodically (every 5 minutes).
pub fn check_time_based_milestones(app: &AppHandle) {
    let state = app.state::<AppState>();
    let store = state.guidance_store.lock().unwrap_or_else(|e| e.into_inner());

    let onboarding_ts = match &store.onboarding_completed_at {
        Some(ts) => match DateTime::parse_from_rfc3339(ts) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => return,
        },
        None => return,
    };

    let now = Utc::now();
    let elapsed = now.signed_duration_since(onboarding_ts);

    // Collect which milestones should fire (to avoid holding the lock during emit)
    let mut to_fire: Vec<String> = Vec::new();

    // restart_reminder: 30 minutes after onboarding, no events yet
    if !store.has_fired("restart_reminder") && elapsed > Duration::minutes(30) {
        let event_count = state
            .event_buffer
            .lock()
            .map(|buf| buf.len())
            .unwrap_or(0);
        if event_count == 0 {
            to_fire.push("restart_reminder".to_string());
        }
    }

    // first_day_summary: 24 hours after onboarding
    if !store.has_fired("first_day_summary") && elapsed > Duration::hours(24) {
        to_fire.push("first_day_summary".to_string());
    }

    // feature_nudge_tools: 3 days, user has not visited /tools
    if !store.has_fired("feature_nudge_tools")
        && elapsed > Duration::days(3)
        && !store.has_visited_page("/tools")
    {
        to_fire.push("feature_nudge_tools".to_string());
    }

    // ai_model_nudge: 5 days, no local model loaded
    if !store.has_fired("ai_model_nudge") && elapsed > Duration::days(5) {
        let has_local = tokio::runtime::Handle::current()
            .block_on(state.ai_backends.local_available());
        if !has_local {
            to_fire.push("ai_model_nudge".to_string());
        }
    }

    // first_week_digest: 7 days after onboarding
    if !store.has_fired("first_week_digest") && elapsed > Duration::days(7) {
        to_fire.push("first_week_digest".to_string());
    }

    drop(store);

    for id in to_fire {
        check_event_milestone(app, &id);
    }
}

/// Start the periodic timer that checks time-based milestones every 5 minutes.
pub fn start_guidance_timer(app: AppHandle) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(300));
            check_time_based_milestones(&app);
        }
    });
}

/// Emit guidance events to the frontend based on the milestone's delivery method.
fn emit_guidance(app: &AppHandle, milestone: &GuidanceMilestone) {
    let event = GuidanceEvent {
        milestone: milestone.clone(),
    };

    let delivery = &milestone.delivery;

    if delivery.contains("toast") {
        let _ = app.emit("rookbot://guidance-toast", &event);
    }
    if delivery.contains("claw_message") {
        let _ = app.emit("rookbot://guidance-claw-message", &event);
    }
    if delivery.contains("inline_hint") {
        let _ = app.emit("rookbot://guidance-hint", &event);
    }
    if delivery.contains("prompt_overlay") {
        let _ = app.emit("rookbot://guidance-overlay", &event);
    }
}
