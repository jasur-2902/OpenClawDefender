//! Template constants for Ask Rook response synthesis.
//!
//! Every user-facing string lives here. Never hardcode a response string
//! in synthesizer.rs — import from this module instead.

// ---------------------------------------------------------------------------
// Status templates
// ---------------------------------------------------------------------------

/// status.overall — all clear
pub const STATUS_OVERALL_CLEAR: &str =
    "All clear. I'm monitoring {server_count} AI tools. Everything's been quiet today.";

/// status.overall — all clear with events
pub const STATUS_OVERALL_CLEAR_WITH_EVENTS: &str =
    "All clear. I'm monitoring {server_count} AI tools. I checked {event_count} actions today — nothing was blocked.";

/// status.overall — some blocked
pub const STATUS_OVERALL_WATCHING: &str =
    "I'm keeping an eye on a few things. I'm monitoring {server_count} AI tools. I checked {event_count} actions today — {blocked_count} were blocked.";

/// status.daemon — running
pub const STATUS_DAEMON_RUNNING: &str =
    "The daemon is running. Uptime: {uptime}. {server_count} servers proxied.";

/// status.daemon — stopped
pub const STATUS_DAEMON_STOPPED: &str =
    "The daemon is stopped. Want me to start it?";

/// status.protection_score
pub const STATUS_PROTECTION_SCORE: &str =
    "Your protection score is {score}. {description}.";

/// status.protection_score — with top factor
pub const STATUS_PROTECTION_SCORE_WITH_FACTOR: &str =
    "Your protection score is {score}. {description}. {top_factor}";

/// status.server_specific — template base
pub const STATUS_SERVER_SPECIFIC: &str =
    "{server_name}: {status}. {event_count} events recorded. {risk_summary}";

// ---------------------------------------------------------------------------
// Activity templates
// ---------------------------------------------------------------------------

/// activity.recent
pub const ACTIVITY_RECENT: &str =
    "Here's what's been happening recently.";

/// activity.blocked
pub const ACTIVITY_BLOCKED: &str =
    "I've blocked {count} actions {time_context}. Here are the most notable:";

/// activity.blocked — none
pub const ACTIVITY_BLOCKED_NONE: &str =
    "I haven't blocked anything {time_context}. Everything's been within policy.";

/// activity.stats
pub const ACTIVITY_STATS: &str =
    "{total} events {time_period}. {blocked} blocked, {allowed} allowed. {notable_summary}";

/// activity.stats — quiet
pub const ACTIVITY_STATS_QUIET: &str =
    "{total} events {time_period}. Nothing was blocked. Things are running smoothly.";

// ---------------------------------------------------------------------------
// Control templates
// ---------------------------------------------------------------------------

/// control.block — confirmation
pub const CONTROL_BLOCK_CONFIRM: &str =
    "I'll add a rule to block {server} from {action}. {impact}. Want me to go ahead?";

/// control.scan — starting
pub const CONTROL_SCAN_START: &str =
    "Starting a security scan now. I'll check your setup for issues.";

/// control.pause — confirmation
pub const CONTROL_PAUSE_CONFIRM: &str =
    "I'll pause protection for {duration}. I'll automatically resume after that. While paused, I won't block or prompt for any actions. Are you sure?";

/// control.allow — confirmation
pub const CONTROL_ALLOW_CONFIRM: &str =
    "I'll add a rule to allow {server} to {action}. Want me to go ahead?";

/// control.start — daemon
pub const CONTROL_START_DAEMON: &str =
    "Starting the daemon now.";

/// control.stop — daemon
pub const CONTROL_STOP_DAEMON: &str =
    "Stopping the daemon. You won't be protected until it's running again.";

// ---------------------------------------------------------------------------
// Navigation templates
// ---------------------------------------------------------------------------

/// navigate.page
pub const NAVIGATE_PAGE: &str = "Opening {page_name}.";

// ---------------------------------------------------------------------------
// Help templates
// ---------------------------------------------------------------------------

/// help.general
pub const HELP_GENERAL: &str =
    "I can help you with a lot of things. Here are some examples:";

/// help.general — fallback
pub const HELP_FALLBACK: &str =
    "I'm not sure what you mean. Here are some things I can help with:";

// ---------------------------------------------------------------------------
// Explain templates
// ---------------------------------------------------------------------------

/// explain.why_blocked — template base
pub const EXPLAIN_WHY_BLOCKED: &str =
    "I blocked that because {reason}. {detail}";

/// explain.concept — LLM unavailable fallback
pub const EXPLAIN_CONCEPT_NO_LLM: &str =
    "I need an AI model loaded to answer that. You can set one up in Settings > AI Engine.";

/// explain.recommendation — LLM unavailable fallback
pub const EXPLAIN_RECOMMENDATION_NO_LLM: &str =
    "I need an AI model loaded to answer that. You can set one up in Settings > AI Engine.";

/// explain.event — template base
pub const EXPLAIN_EVENT: &str =
    "Here's what happened: {summary}. {detail}";

// ---------------------------------------------------------------------------
// Risk templates
// ---------------------------------------------------------------------------

/// risk.server — template base
pub const RISK_SERVER: &str =
    "Here's what I know about {server_name}. {reputation}. {profile_summary}";

// ---------------------------------------------------------------------------
// LLM system prompt
// ---------------------------------------------------------------------------

/// System prompt for LLM-assisted responses.
pub const LLM_SYSTEM_PROMPT: &str =
    "You are Claw, a calm, direct security companion. Respond in first person. \
     Keep responses under 3 sentences for summaries. Use plain language. \
     Reference the user's specific data. No exclamation marks. No jargon without explanation.";

// ---------------------------------------------------------------------------
// Suggestion sets by intent
// ---------------------------------------------------------------------------

pub const SUGGESTIONS_STATUS_OVERALL: &[&str] = &[
    "What happened today?",
    "Scan my setup",
    "Show me threats",
];

pub const SUGGESTIONS_STATUS_DAEMON: &[&str] = &[
    "How's everything?",
    "Show recent activity",
    "What's my protection score?",
];

pub const SUGGESTIONS_STATUS_PROTECTION_SCORE: &[&str] = &[
    "How do I improve my score?",
    "Show me what's missing",
    "Scan my setup",
];

pub const SUGGESTIONS_STATUS_SERVER: &[&str] = &[
    "Should I be worried?",
    "Show me its recent activity",
    "Block this server",
];

pub const SUGGESTIONS_ACTIVITY_RECENT: &[&str] = &[
    "What was blocked?",
    "Are there any threats?",
    "How's everything?",
];

pub const SUGGESTIONS_ACTIVITY_BLOCKED: &[&str] = &[
    "Why was that blocked?",
    "Show me all activity",
    "Tighten my security",
];

pub const SUGGESTIONS_ACTIVITY_STATS: &[&str] = &[
    "Show me recent events",
    "What was blocked?",
    "How's everything?",
];

pub const SUGGESTIONS_CONTROL_BLOCK: &[&str] = &[
    "What else has {server} been doing?",
    "Tighten my security",
    "Show me threats",
];

pub const SUGGESTIONS_CONTROL_SCAN: &[&str] = &[
    "How's everything?",
    "Show me threats",
    "What's my protection score?",
];

pub const SUGGESTIONS_CONTROL_PAUSE: &[&str] = &[
    "Resume protection",
    "How's everything?",
    "What did I miss?",
];

pub const SUGGESTIONS_NAVIGATE: &[&str] = &[
    "How's everything?",
    "What happened today?",
    "Show me threats",
];

pub const SUGGESTIONS_HELP: &[&str] = &[
    "Am I safe?",
    "What happened today?",
    "Scan my setup",
];

pub const SUGGESTIONS_EXPLAIN_EVENT: &[&str] = &[
    "Should I be worried?",
    "Block this server",
    "Show me more events",
];

pub const SUGGESTIONS_EXPLAIN_CONCEPT: &[&str] = &[
    "How's everything?",
    "Show me threats",
    "Scan my setup",
];

pub const SUGGESTIONS_RISK: &[&str] = &[
    "Block this server",
    "Show me its activity",
    "Scan my setup",
];

pub const SUGGESTIONS_FALLBACK: &[&str] = &[
    "Am I safe?",
    "What happened today?",
    "Show me threats",
];

// ---------------------------------------------------------------------------
// Help examples shown in help.general
// ---------------------------------------------------------------------------

pub const HELP_EXAMPLES: &[&str] = &[
    "Am I safe?",
    "What happened today?",
    "What's my protection score?",
    "Scan my setup",
    "Block a server",
    "Show me recent activity",
    "Why was something blocked?",
    "Tell me about a specific server",
];

// ---------------------------------------------------------------------------
// Page name mappings for navigate intent
// ---------------------------------------------------------------------------

pub const PAGE_NAMES: &[(&str, &str)] = &[
    ("dashboard", "the Dashboard"),
    ("activity", "the Activity Log"),
    ("alerts", "Alerts"),
    ("guards", "Guards"),
    ("scanner", "the Scanner"),
    ("policy", "the Policy Editor"),
    ("settings", "Settings"),
    ("behavioral", "Behavioral Analysis"),
    ("network", "Network Log"),
    ("my-tools", "My Tools"),
];

/// Look up a human-readable page name.
pub fn page_display_name(page_id: &str) -> &str {
    PAGE_NAMES
        .iter()
        .find(|(id, _)| *id == page_id)
        .map(|(_, name)| *name)
        .unwrap_or(page_id)
}

// ---------------------------------------------------------------------------
// Action button labels
// ---------------------------------------------------------------------------

pub const ACTION_CONFIRM: &str = "Do it";
pub const ACTION_CANCEL: &str = "Never mind";
pub const ACTION_PAUSE_CONFIRM: &str = "Pause";
pub const ACTION_PAUSE_CANCEL: &str = "Keep protecting";
pub const ACTION_START_DAEMON: &str = "Start daemon";
