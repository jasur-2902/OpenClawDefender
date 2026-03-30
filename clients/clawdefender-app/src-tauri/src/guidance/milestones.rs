use serde::{Deserialize, Serialize};

/// A guidance milestone that fires exactly once to teach the user during their
/// first week with ClawDefender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceMilestone {
    pub id: String,
    pub title: String,
    pub trigger_type: String,
    pub message: String,
    /// How the milestone is delivered: "claw_message", "toast", "inline_hint", "prompt_overlay"
    pub delivery: String,
    /// Optional metadata for delivery (e.g., page, anchor for hints).
    pub delivery_meta: Option<serde_json::Value>,
    pub fired: bool,
    pub fired_at: Option<String>,
    pub dismissed: bool,
}

/// All 9 milestone definitions with their default (unfired) state.
pub fn all_milestones() -> Vec<GuidanceMilestone> {
    vec![
        GuidanceMilestone {
            id: "first_prompt".to_string(),
            title: "Your first decision".to_string(),
            trigger_type: "event".to_string(),
            message: "This is your first decision. I paused this action because it looked risky. \
                You can allow it, block it, or tell me to always handle actions like this. \
                Take your time.".to_string(),
            delivery: "prompt_overlay".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "first_block".to_string(),
            title: "First block".to_string(),
            trigger_type: "event".to_string(),
            message: "I just blocked something for the first time. This is exactly what I am \
                here for. You can review the details anytime.".to_string(),
            delivery: "toast+claw_message".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "behavioral_complete".to_string(),
            title: "Behavioral learning complete".to_string(),
            trigger_type: "event".to_string(),
            message: "I have learned how this server normally behaves. From now on, I will notice \
                if it does something unusual. This is one of my most powerful protections.".to_string(),
            delivery: "claw_message".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "first_day_summary".to_string(),
            title: "Your first day".to_string(),
            trigger_type: "time".to_string(),
            message: "Your first day with me is complete. Everything is running smoothly. \
                I will keep watching.".to_string(),
            delivery: "claw_message".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "score_drop_below_70".to_string(),
            title: "Protection score dropped".to_string(),
            trigger_type: "event".to_string(),
            message: "Your protection score dropped. Let me help you fix it.".to_string(),
            delivery: "toast+claw_message".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "first_week_digest".to_string(),
            title: "Your first week".to_string(),
            trigger_type: "time".to_string(),
            message: "Your first week is complete. You are getting the hang of this. I will send \
                you a summary like this every week.".to_string(),
            delivery: "claw_message".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "feature_nudge_tools".to_string(),
            title: "Explore your tools".to_string(),
            trigger_type: "time".to_string(),
            message: "Tip: Visit My Tools to see what each of your AI tools can do and customize \
                their trust levels.".to_string(),
            delivery: "inline_hint".to_string(),
            delivery_meta: Some(serde_json::json!({
                "page": "/",
                "anchor": "server-section"
            })),
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "ai_model_nudge".to_string(),
            title: "Level up your protection".to_string(),
            trigger_type: "time".to_string(),
            message: "You are running without an AI model. I can still protect you with rules, \
                but a local model helps me understand context. Set one up in Settings.".to_string(),
            delivery: "claw_message+inline_hint".to_string(),
            delivery_meta: Some(serde_json::json!({
                "page": "/",
                "anchor": "pending-actions"
            })),
            fired: false,
            fired_at: None,
            dismissed: false,
        },
        GuidanceMilestone {
            id: "restart_reminder".to_string(),
            title: "Restart your AI tools".to_string(),
            trigger_type: "time".to_string(),
            message: "Your AI tools are not routing through me yet. Restart them so I can start \
                monitoring.".to_string(),
            delivery: "toast".to_string(),
            delivery_meta: None,
            fired: false,
            fired_at: None,
            dismissed: false,
        },
    ]
}
