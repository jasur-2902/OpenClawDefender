use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Listener, Manager};

use crate::state::AppState;
use super::calculator;
use super::history;

/// Tauri event name emitted when the score changes.
pub const SCORE_CHANGED_EVENT: &str = "clawdefender://score-changed";

/// Debounce interval for score recalculation.
const DEBOUNCE_MS: u64 = 2000;

/// Global debounce state: a mutex-wrapped optional JoinHandle.
/// Using a lazy static since we cannot store tokio handles in AppState (not Send).
static DEBOUNCE_HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

/// Request a debounced score recalculation.
///
/// If a recalculation is already pending, it is cancelled and a new 2-second
/// timer starts. When the timer fires, the score is recomputed and, if changed,
/// a `clawdefender://score-changed` event is emitted.
pub fn request_recalculation(app: &AppHandle) {
    let app = app.clone();

    if let Ok(mut handle) = DEBOUNCE_HANDLE.lock() {
        // Cancel pending timer
        if let Some(h) = handle.take() {
            h.abort();
        }

        let join = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;
            do_recalculate(&app);
        });

        *handle = Some(join);
    }
}

/// Perform the actual score recalculation, persistence, and event emission.
pub fn do_recalculate(app: &AppHandle) {
    let state = app.state::<AppState>();
    let score = calculator::compute_score(&state);

    // Serialize factors for storage
    let factors_json = serde_json::to_string(&score.factors).unwrap_or_default();

    // Persist snapshot (deduplicates internally)
    history::store_snapshot(score.total, &factors_json, &score.computed_at);

    // Emit event to frontend
    let _ = app.emit(SCORE_CHANGED_EVENT, &score);

    // Cache in state
    if let Ok(mut cached) = state.cached_score.lock() {
        *cached = Some(score);
    }

    // Periodically vacuum old history (run every ~100 recalculations is fine,
    // but simpler to just vacuum on each change since it's cheap)
    history::vacuum(90);
}

/// Start listening for events that should trigger score recalculation.
///
/// Call this once during app setup. It subscribes to relevant Tauri events
/// and requests a debounced recalculation when any fires.
pub fn start_score_listeners(app: &AppHandle) {
    let events_to_watch = [
        "clawdefender://event",
        "clawdefender://alert",
        "clawdefender://status-change",
        "clawdefender://new-tool-detected",
        "clawdefender://server-wrapped",
        "clawdefender://server-unwrapped",
        "clawdefender://trust-changed",
        "clawdefender://policy-changed",
        "clawdefender://model-activated",
        "clawdefender://model-deactivated",
        "clawdefender://feed-updated",
        "clawdefender://alert-dismissed",
        "clawdefender://alert-resolved",
        "clawdefender://settings-changed",
        "clawdefender://autostart-changed",
    ];

    for event_name in events_to_watch {
        let app_clone = app.clone();
        app.listen(event_name, move |_| {
            request_recalculation(&app_clone);
        });
    }

    // Compute initial score on startup
    do_recalculate(app);
}
