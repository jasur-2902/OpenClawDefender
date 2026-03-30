# Step 6: Activity & Alerts Architecture

**Version**: 1.0
**Date**: 2026-02-25
**Status**: Design Complete

This document defines the complete architecture for Step 6 -- event humanization, alert intelligence, notification routing, kill chain narratives, weekly digests, recommendations, and correlation display.

---

## 1. Event Humanization Pipeline

Events flow through four stages from raw `AuditEvent` to the user's screen:

```
AuditEvent (Rust)
    |
    v
[1. Event Enricher] -- adds behavioral context from ServerProfileSummary
    |
    v
[2. Event Humanizer] -- generates one-liner, explanation, educational aside
    |
    v
[3. Alert Generator] -- promotes to alert when conditions are met
    |
    v
[4. Notification Router] -- determines delivery channel
    |
    v
HumanizedEvent (emitted to frontend via Tauri event)
```

### Stage 1: Event Enricher

**Input**: `AuditEvent` + `ServerProfileSummary` (from `summaries.rs`)

**Output**: `EnrichedEvent`

```rust
// src-tauri/src/humanizer.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralContext {
    /// e.g. "This happens about 40 times a day", "First time ever", "Still learning"
    pub frequency_description: String,
    /// "learning" | "active" | "new"
    pub profile_status: String,
    /// Number of times this server+tool+action combo has been seen
    pub historical_count: u64,
    /// True if this specific action has never been seen from this server
    pub is_first_occurrence: bool,
    /// Anomaly score from ServerProfileSummary (0.0 - 1.0)
    pub anomaly_score: f64,
    /// Trust recommendation from summaries.rs: "trusted" | "standard" | "cautious" | "restricted"
    pub trust_recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    pub event: AuditEvent,
    pub behavioral_context: BehavioralContext,
    pub server_display_name: String,
    pub client_name: Option<String>,
}
```

**How it works**: The enricher looks up the server in the event buffer (`AppState.event_buffer`) to compute `historical_count` and `is_first_occurrence`. It reads `ServerProfileSummary` from the behavioral DB via `read_profiles_from_db_for_server()`. For servers still in learning phase, it sets `profile_status = "learning"`.

### Stage 2: Event Humanizer

**Input**: `EnrichedEvent`

**Output**: `HumanizedEvent`

The humanizer pattern-matches on the event fields to select a template from the template table (Section 3), then interpolates the event data into the template strings.

```rust
// src-tauri/src/humanizer.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HumanizedEvent {
    /// Original event ID
    pub event_id: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Human-friendly server name (e.g. "filesystem" not "mcp-server-filesystem")
    pub server_display_name: String,
    /// MCP client name if known (e.g. "Cursor", "Claude Desktop")
    pub client_name: Option<String>,

    // --- Human-readable content ---

    /// One-liner for feed and notifications (max ~80 chars)
    /// e.g. "Cursor read 3 files in your project directory."
    pub one_liner: String,
    /// 2-3 sentence explanation for detail views
    pub expanded_explanation: String,
    /// Optional educational context for medium+ risk events
    pub educational_aside: Option<String>,

    // --- Behavioral context ---

    /// e.g. "This happens about 40 times a day" / "First time ever" / "Still learning"
    pub behavioral_context: String,

    // --- Risk assessment ---

    /// Mapped threat level: "dangerous" | "suspicious" | "unusual" | "normal" | "blocked" | "info"
    pub risk_level: String,
    /// Human explanation of why this risk level was assigned
    pub risk_explanation: String,

    // --- Action taken ---

    /// "Allowed" | "Blocked" | "Prompted" | "AutoBlocked"
    pub action_taken: String,
    /// Why this action was taken (e.g. "Matched policy rule: block SSH access")
    pub action_reason: String,

    // --- Flags ---

    /// Should this event stand out in the feed? (blocked, high risk, first occurrence, etc.)
    pub is_notable: bool,

    // --- Correlation ---

    /// Groups related events (same server + similar timing)
    pub correlation_id: Option<String>,
    /// If this event is part of a detected kill chain
    pub kill_chain_id: Option<String>,

    // --- Raw data ---

    /// Original AuditEvent for "Show technical details" toggle
    pub raw_event: AuditEvent,
}
```

### TypeScript Interface (frontend mirror)

```typescript
// src/types/index.ts

export interface HumanizedEvent {
  event_id: string;
  timestamp: string;
  server_display_name: string;
  client_name: string | null;
  one_liner: string;
  expanded_explanation: string;
  educational_aside: string | null;
  behavioral_context: string;
  risk_level: "dangerous" | "suspicious" | "unusual" | "normal" | "blocked" | "info";
  risk_explanation: string;
  action_taken: "Allowed" | "Blocked" | "Prompted" | "AutoBlocked";
  action_reason: string;
  is_notable: boolean;
  correlation_id: string | null;
  kill_chain_id: string | null;
  raw_event: AuditEvent;
}
```

### Stage 3: Alert Generator (Rust)

See Section 5 (Alert Intelligence Model).

### Stage 4: Notification Router

See Section 7 (Notification Routing Matrix).

---

## 2. Event Classification Patterns

The humanizer classifies events by matching against these patterns in order. First match wins.

| # | Pattern | Match Criteria |
|---|---------|---------------|
| 1 | SSH key access | `resource` contains `.ssh/id_rsa` or `.ssh/id_ed25519` or `.ssh/id_ecdsa` |
| 2 | AWS credentials | `resource` contains `.aws/credentials` or `.aws/config` |
| 3 | Env file access | `resource` ends with `.env` or contains `.env.` |
| 4 | Browser data | `resource` contains `Cookies`, `Login Data`, `cookies.sqlite`, `logins.json` |
| 5 | High-risk shell command | `action` matches shell exec AND `resource`/`details` contains `curl\|bash`, `wget\|sh`, `rm -rf`, `chmod 777`, `eval` |
| 6 | Safe shell command | `action` matches shell exec AND command is `ls`, `pwd`, `echo`, `cat`, `which`, `grep`, `find`, `git` |
| 7 | Network: known API | `event_type` is network AND `resource` matches known API domains (anthropic, openai, github, etc.) |
| 8 | Network: malicious/IoC | `details` contains `ioc` or `blocklist` or `malicious` |
| 9 | Network: unknown | `event_type` is network AND does not match patterns 7 or 8 |
| 10 | Sampling/createMessage | `action` contains `sampling` or `createMessage` |
| 11 | Prompt injection | `details` contains `injection` or `prompt injection` |
| 12 | Kill chain step | `details` contains `kill chain` or `kill_chain` |
| 13 | Discovery request | `action` is `tools/list`, `resources/list`, `prompts/list` or event_summary matches |
| 14 | Session start | `action` is `Session Started` or `event_summary` is `session-start` |
| 15 | Session end | `action` is `Session Ended` or `event_summary` is `session-end` |
| 16 | File read (project) | `tool_name` is `read_file` or action contains `read` AND resource is within project directory |
| 17 | File read (sensitive) | `tool_name` is `read_file` AND resource is outside project or in sensitive path |
| 18 | File write | `tool_name` is `write_file` or `create_file` or action contains `write`/`create` |
| 19 | Auto-block | `decision` is `blocked`/`denied` AND `details` contains `auto` |
| 20 | Policy prompt | `decision` is `prompted` |
| 21 | First-time action | `is_first_occurrence` is true (from BehavioralContext) |
| 22 | Activity rate spike | Activity rate exceeds 3x learned mean (from ActivityPattern) |
| 23 | Out-of-territory | Resource path not in server's known territory directories |
| 24 | Uncorrelated OS | `details` contains `uncorrelated` |
| 25 | Generic fallback | Everything else |

---

## 3. Event Humanization Templates (25+)

Each template produces: `one_liner`, `expanded_explanation`, `educational_aside` (optional), `behavioral_context`, and `risk_explanation`.

Template variables: `{server}`, `{tool}`, `{resource}`, `{command}`, `{destination}`, `{count}`, `{rate}`, `{client}`.

### Template 1: SSH Key Access

- **One-liner**: `{server} tried to read your SSH private key. I paused it.`
- **Expanded**: `The server "{server}" made a tool call that attempted to open {resource}. SSH private keys grant access to remote servers, so I paused this and I am asking you before it goes further.`
- **Educational**: `SSH keys are like master passwords to your servers. A legitimate server rarely needs to read the private key itself.`
- **Behavioral**: `{behavioral_context}` (from enricher)
- **Risk**: `This targets a sensitive credential file. Risk level: dangerous.`

### Template 2: AWS Credentials

- **One-liner**: `{server} tried to access your AWS credentials. Paused.`
- **Expanded**: `The server "{server}" attempted to read your AWS credentials file at {resource}. This file contains secret keys that could give access to your cloud infrastructure.`
- **Educational**: `If a server needs AWS access, it is safer to use environment variables with limited-scope IAM roles than to expose your credentials file.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Cloud credential files contain keys to your infrastructure. Risk level: dangerous.`

### Template 3: Env File Access

- **One-liner**: `{server} tried to read environment secrets at {resource}.`
- **Expanded**: `The server "{server}" attempted to read {resource}. Environment files often contain API keys, database passwords, and other secrets.`
- **Educational**: `.env files are a common target because they concentrate secrets in a single readable file.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Environment files frequently contain secrets. Risk level: suspicious.`

### Template 4: Browser Data Access

- **One-liner**: `{server} tried to access your browser passwords. Blocked.`
- **Expanded**: `The server "{server}" attempted to read a browser password or cookie database at {resource}. There is no legitimate reason for an MCP server to access browser credentials. I blocked this automatically.`
- **Educational**: (none -- the expanded is sufficient)
- **Behavioral**: `This has never happened before. This server has no history of browser access.`
- **Risk**: `Browser credential databases are never a valid target for MCP servers. Risk level: dangerous.`

### Template 5: High-Risk Shell Command

- **One-liner**: `{server} tried to run a dangerous shell command. Paused.`
- **Expanded**: `The server "{server}" attempted to execute "{command}". This type of command can download and run arbitrary code or permanently delete files. I paused it for your review.`
- **Educational**: `Piping a download directly into a shell (curl | bash) runs whatever code is on the other end with no review. It is one of the most common ways malicious code gets executed.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `This command pattern is associated with remote code execution or destructive operations. Risk level: dangerous.`

### Template 6: Safe Shell Command

- **One-liner**: `{server} ran a shell command: {command}`
- **Expanded**: `The server "{server}" executed {command} in your project directory. This is a routine command within the expected working area.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `This is a standard development command. Risk level: normal.`

### Template 7: Network Connection (Known API)

- **One-liner**: `{server} connected to {destination}. Expected.`
- **Expanded**: `The server "{server}" made a network connection to {destination}, which is a recognized AI provider API. This is normal behavior for this type of server.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Connection to a recognized API endpoint. Risk level: normal.`

### Template 8: Network Connection (Malicious/IoC)

- **One-liner**: `{server} tried to contact a known malicious host. Blocked.`
- **Expanded**: `The server "{server}" attempted to connect to {destination}, which is flagged in threat intelligence feeds as malicious. I blocked the connection. This could indicate a compromised MCP server.`
- **Educational**: `Indicators of Compromise (IoCs) are addresses, file hashes, and patterns that have been observed in real-world attacks and shared by the security community.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `This destination matches known malicious infrastructure. Risk level: dangerous.`

### Template 9: Network Connection (Unknown)

- **One-liner**: `{server} connected to an unfamiliar address: {destination}.`
- **Expanded**: `The server "{server}" connected to {destination}. I do not recognize this destination, and it is not in any allowlist. It could be legitimate, but I have not seen this server connect here before.`
- **Educational**: `MCP servers normally only respond to your AI tool -- they do not usually reach out to the internet on their own.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Unknown destination not in any allowlist. Risk level: unusual.`

### Template 10: Sampling/createMessage

- **One-liner**: `{server} sent an AI sampling request.`
- **Expanded**: `The server "{server}" sent a sampling/createMessage request, asking to generate AI content. This is the MCP mechanism for servers to use AI capabilities.`
- **Educational**: `sampling/createMessage lets a server ask your AI tool to generate text. A compromised server could use this to manipulate AI outputs.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `AI sampling requests can be used to influence model outputs. Risk level: unusual.`

### Template 11: Prompt Injection

- **One-liner**: `I found a prompt injection attempt in a message from {server}.`
- **Expanded**: `The server "{server}" sent a sampling/createMessage request containing text that looks like a prompt injection attack. The suspicious content attempts to override your AI's instructions. I blocked the message.`
- **Educational**: `Prompt injection is when hidden instructions are smuggled into AI inputs, trying to override the AI's original instructions. It is one of the most common attack vectors for AI agents.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Prompt injection attacks can cause AI tools to act against your interests. Risk level: dangerous.`

### Template 12: Kill Chain Step

- **One-liner**: `I detected a multi-step attack pattern from {server}.`
- **Expanded**: `The server "{server}" executed a sequence of actions that matches a known attack pattern. See the attack chain timeline for the full sequence.`
- **Educational**: `A kill chain is a sequence of actions that individually might seem harmless but together form an attack -- like reading credentials, then connecting to the internet.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Multi-step attack pattern detected. Risk level: dangerous.`

### Template 13: Uncorrelated OS Activity

- **One-liner**: `I noticed system activity that does not match any server request.`
- **Expanded**: `A system event occurred ({details}) that I cannot trace back to any MCP tool call or resource read. This could be normal background activity, or it could be a process acting on its own outside the MCP protocol.`
- **Educational**: `MCP servers should do their work through the protocol. Activity that happens outside the protocol could mean a server is doing things behind the scenes.`
- **Behavioral**: `No matching MCP request found in the last 60 seconds.`
- **Risk**: `Uncorrelated system activity warrants investigation. Risk level: suspicious.`

### Template 14: Auto-Block

- **One-liner**: `I blocked this automatically -- it looked dangerous.`
- **Expanded**: `I blocked an action by "{server}" automatically because it combined multiple high-risk signals. Auto-blocking is enabled in your settings and activates when the risk level is very high. You can review this decision and override it.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Multiple high-risk signals combined. Risk level: dangerous.`

### Template 15: Policy Prompt

- **One-liner**: `{server} wants to {action}. Your call.`
- **Expanded**: `The server "{server}" is requesting permission to {action} on {resource}. Your policy requires approval for this type of action.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Your policy requires human approval for this action.`

### Template 16: Session Start

- **One-liner**: `{server} session started.`
- **Expanded**: `A new session for the server "{server}" has begun. I am monitoring all actions from this point.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Session lifecycle event. Risk level: info.`

### Template 17: Session End

- **One-liner**: `{server} session ended.`
- **Expanded**: `The session for "{server}" has ended. All actions during this session were logged.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Session lifecycle event. Risk level: info.`

### Template 18: Discovery Request

- **One-liner**: `{server} requested a list of available tools.`
- **Expanded**: `The server "{server}" sent a discovery request to list available tools or resources. This is standard MCP protocol behavior during initialization.`
- **Educational**: `MCP servers discover their capabilities through list requests. This is normal startup behavior.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Standard protocol discovery. Risk level: info.`

### Template 19: File Read (Project)

- **One-liner**: `{server} read {resource}.`
- **Expanded**: `The server "{server}" read the file {resource} in your project directory. This is within the server's expected working area.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `File access within project directory. Risk level: normal.`

### Template 20: File Read (Sensitive Path)

- **One-liner**: `{server} accessed a file outside your project: {resource}.`
- **Expanded**: `The server "{server}" read {resource}, which is outside your current project directory. This could be a normal config lookup, but I wanted you to know.`
- **Educational**: `Files outside your project directory may contain sensitive configuration or system data.`
- **Behavioral**: `{behavioral_context}`
- **Risk**: `Access outside expected territory. Risk level: unusual.`

### Template 21: File Write

- **One-liner**: `{server} wrote to {resource}.`
- **Expanded**: `The server "{server}" created or modified the file {resource}. File modifications are logged for your records.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `File modification within expected area. Risk level: normal.`

### Template 22: First-Time Action

- **One-liner**: `{server} just used {tool} for the first time.`
- **Expanded**: `The server "{server}" called the tool "{tool}" for the first time. Based on its learned behavior profile, this tool has not been part of its normal operation. This could be a new workflow or something unexpected.`
- **Educational**: (none)
- **Behavioral**: `This is the first time this server has used this tool. Previous sessions only used {known_tools}.`
- **Risk**: `New behavior from a server with an established profile. Risk level: unusual.`

### Template 23: Activity Rate Spike

- **One-liner**: `{server} is working much faster than normal.`
- **Expanded**: `The server "{server}" is making requests at {rate} its usual pace. A sudden spike in activity can indicate automated behavior or a compromised server.`
- **Educational**: (none)
- **Behavioral**: `Normal rate: ~{normal_rate} actions/hour. Current rate: ~{current_rate} actions/hour.`
- **Risk**: `Activity rate exceeds 3x normal baseline. Risk level: suspicious.`

### Template 24: Out-of-Territory Access

- **One-liner**: `{server} accessed a path outside its usual territory.`
- **Expanded**: `The server "{server}" accessed {resource}, which is outside the directories it normally works in ({territory_list}). This could be legitimate, but it is outside the learned pattern.`
- **Educational**: (none)
- **Behavioral**: `This server normally works in: {territory_list}. Today it accessed {resource}.`
- **Risk**: `Access outside learned territory boundaries. Risk level: unusual.`

### Template 25: Generic Fallback

- **One-liner**: `{server} performed {action}.`
- **Expanded**: `The server "{server}" performed the action "{action}". No specific risk pattern was matched.`
- **Educational**: (none)
- **Behavioral**: `{behavioral_context}`
- **Risk**: `No specific risk pattern matched. Risk level: normal.`

---

## 4. Behavioral Context Templates

The `behavioral_context` field is generated from `BehavioralContext` using these rules:

| Condition | Output |
|-----------|--------|
| `profile_status == "learning"` | `I am still learning this server's patterns. {events_needed} more events until baseline.` |
| `is_first_occurrence && profile_status == "active"` | `First time this server has done this. All previous sessions used {known_tools}.` |
| `historical_count == 0` | `This is new behavior for this server.` |
| `historical_count < 5` | `This server has done this {count} time(s) before.` |
| `historical_count >= 5 && historical_count < 50` | `This happens regularly -- about {rate} times per session.` |
| `historical_count >= 50` | `This is routine -- about {daily_rate} times per day.` |
| `anomaly_score >= 0.7` | `This server's recent behavior has been unusual. I am watching it more closely.` |
| `anomaly_score < 0.1 && historical_count > 100` | `This server's behavior has been completely consistent.` |

---

## 5. Alert Intelligence Model

### Alert Promotion Conditions

Events are promoted to alerts when any of these conditions are met:

| # | Condition | Alert Type | Severity | Auto-Resolve Rule |
|---|-----------|------------|----------|-------------------|
| 1 | `anomaly_score >= 0.7` | Anomaly Alert | Suspicious | After 24 hours with no recurrence |
| 2 | Kill chain pattern detected | Kill Chain Alert | Dangerous | Never auto-resolves |
| 3 | Auto-block triggered | Block Alert | Blocked | After 1 hour if no user review |
| 4 | IoC match in event details | Threat Intel Alert | Dangerous | Never auto-resolves |
| 5 | Uncorrelated OS activity detected | Correlation Alert | Suspicious | After 12 hours with no recurrence |
| 6 | Prompt timed out (auto-denied) | Timeout Alert | Info | After 4 hours |
| 7 | New unwrapped server detected | Discovery Alert | Info | After 7 days or when server is wrapped |
| 8 | Blocklist match on server | Vulnerability Alert | Dangerous | Never auto-resolves |
| 9 | SLM analysis returns HIGH/CRITICAL | Analysis Alert | Suspicious | After 24 hours with no recurrence |

### Alert Lifecycle

```
Created -> Active -> [Reviewed | Resolved | Dismissed | AutoExpired]
```

- **Created**: Alert is generated by the alert engine.
- **Active**: Alert is visible to the user in the Alerts page.
- **Reviewed**: User has viewed the alert details.
- **Resolved**: User explicitly marked as resolved (with optional "allow" action).
- **Dismissed**: User explicitly dismissed without resolving.
- **AutoExpired**: Alert auto-resolved per the rules above.

### Rust Structs

```rust
// src-tauri/src/alert_engine.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    Anomaly,
    KillChain,
    Block,
    ThreatIntel,
    Correlation,
    Timeout,
    Discovery,
    Vulnerability,
    Analysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertLifecycle {
    Active,
    Reviewed,
    Resolved,
    Dismissed,
    AutoExpired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligentAlert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: String,           // "dangerous" | "suspicious" | "unusual" | "info"
    pub lifecycle: AlertLifecycle,

    // Content (humanized)
    pub title: String,              // One-liner from humanized event
    pub description: String,        // Expanded explanation
    pub recommendation: String,     // What to do about it

    // Source
    pub event_ids: Vec<String>,     // Events that triggered this alert
    pub server_name: String,
    pub kill_chain_id: Option<String>,

    // Timing
    pub created_at: String,
    pub updated_at: String,
    pub reviewed_at: Option<String>,
    pub resolved_at: Option<String>,
    pub auto_expire_at: Option<String>,

    // Dedup
    pub occurrence_count: u32,      // How many times this pattern repeated
    pub dedup_key: String,          // For matching duplicates
}
```

### TypeScript Interface

```typescript
// src/types/index.ts

export type AlertType =
  | "Anomaly" | "KillChain" | "Block" | "ThreatIntel"
  | "Correlation" | "Timeout" | "Discovery" | "Vulnerability" | "Analysis";

export type AlertLifecycle = "Active" | "Reviewed" | "Resolved" | "Dismissed" | "AutoExpired";

export interface IntelligentAlert {
  id: string;
  alert_type: AlertType;
  severity: "dangerous" | "suspicious" | "unusual" | "info";
  lifecycle: AlertLifecycle;
  title: string;
  description: string;
  recommendation: string;
  event_ids: string[];
  server_name: string;
  kill_chain_id: string | null;
  created_at: string;
  updated_at: string;
  reviewed_at: string | null;
  resolved_at: string | null;
  auto_expire_at: string | null;
  occurrence_count: number;
  dedup_key: string;
}
```

---

## 6. Alert Deduplication Rules

Alerts are deduplicated before being stored. Rules are checked in order:

| # | Rule | Dedup Key | Window | Behavior |
|---|------|-----------|--------|----------|
| 1 | Same server + action + target | `{server}:{action}:{resource_prefix}` | 5 minutes | Single alert, `occurrence_count++` |
| 2 | Kill chain supersedes individuals | `killchain:{server}:{pattern}` | 60 seconds | Individual alerts are subsumed; only the kill chain alert remains |
| 3 | Auto-blocks of same pattern | `autoblock:{server}:{action}` | 1 hour | Single alert with count badge |
| 4 | IoC match alerts | `ioc:{server}:{destination}` | NEVER | Each IoC match is a separate alert |

**Dedup key construction**: `{alert_type}:{server_name}:{action_or_pattern}:{resource_prefix_2_levels}`

When a duplicate is found within the dedup window:
1. Increment `occurrence_count` on the existing alert
2. Append the new `event_id` to `event_ids`
3. Update `updated_at` timestamp
4. Do NOT create a new alert

---

## 7. Notification Routing Matrix

The notification router receives each `HumanizedEvent` (and any generated `IntelligentAlert`) and determines the delivery channel.

### Decision Tree

| Priority | Condition | Channel | Sound | Persist |
|----------|-----------|---------|-------|---------|
| 1 | `decision == "prompted"` (policy prompt) | Full Prompt Window | Yes | Until user responds or timeout |
| 2 | `severity == "dangerous"` alert | macOS notification + tray flash + in-app AlertWindow | Yes | Until dismissed |
| 3 | `severity == "suspicious"` alert | macOS notification (no sound) + in-app alert card | No | Until reviewed |
| 4 | `action_taken == "AutoBlocked"` | In-app toast (5s) + feed entry | No | Auto-dismiss 5s |
| 5 | `severity == "info"` alert (discovery, timeout) | In-app toast (4s) + feed entry | No | Auto-dismiss 4s |
| 6 | `risk_level == "unusual"` | Feed entry only (subtle highlight) | No | Persistent in feed |
| 7 | `risk_level == "normal"` | Feed entry only | No | Persistent in feed |
| 8 | Session start/end, discovery, protocol handshake | Silent (audit log only) | No | Not in feed |

### Suppression Rules

1. **Foreground app suppression**: If the main window is focused, skip macOS native notifications (already visible in-app).
2. **Rate batching**: If more than 10 events arrive within 5 seconds, batch them into a single summary notification: `"{count} events from {server} in the last few seconds."`.
3. **Quiet hours**: If the user has quiet hours configured (from `config.toml` `ui.quiet_hours_start` / `ui.quiet_hours_end`), suppress all sounds and macOS notifications. In-app UI still shows everything.
4. **Dedup suppression**: If the same dedup_key was notified within the last 5 minutes, do not send a duplicate native notification.

### Rust Implementation

```rust
// src-tauri/src/notification_router.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationChannel {
    PromptWindow,
    AlertWindow { sound: bool },
    NativeNotification { sound: bool },
    Toast { duration_seconds: u32 },
    FeedOnly { highlight: bool },
    Silent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub channels: Vec<NotificationChannel>,
    pub suppressed: bool,
    pub suppression_reason: Option<String>,
}

pub fn route_event(
    event: &HumanizedEvent,
    alert: Option<&IntelligentAlert>,
    window_focused: bool,
    quiet_hours: bool,
) -> RoutingDecision {
    // Implementation follows decision tree above
}
```

---

## 8. Kill Chain Narrative Model

Kill chains are detected from event sequences since no behavioral engine crate exists. Detection works purely from `AuditEvent` patterns in the event buffer.

### KillChainNarrative Struct

```rust
// src-tauri/src/kill_chain.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainNarrative {
    pub id: String,
    pub server_name: String,
    pub pattern_name: String,              // e.g. "credential_exfiltration"
    pub detected_at: String,
    pub steps: Vec<KillChainStep>,
    pub verdict: String,                   // Human-readable verdict
    pub recommended_action: String,
    pub blocked_at_step: Option<u32>,      // Which step was blocked (0-indexed)
    pub severity: String,                  // Always "dangerous"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStep {
    pub step_number: u32,
    pub timestamp: String,
    pub event_id: String,
    pub description: String,              // Humanized description
    pub action_type: String,              // "file_read" | "file_write" | "network" | "exec" | "discovery"
    pub severity: String,                 // "dangerous" | "suspicious" | "unusual"
    pub was_blocked: bool,
}
```

### TypeScript Interface

```typescript
export interface KillChainNarrative {
  id: string;
  server_name: string;
  pattern_name: string;
  detected_at: string;
  steps: KillChainStep[];
  verdict: string;
  recommended_action: string;
  blocked_at_step: number | null;
  severity: "dangerous";
}

export interface KillChainStep {
  step_number: number;
  timestamp: string;
  event_id: string;
  description: string;
  action_type: "file_read" | "file_write" | "network" | "exec" | "discovery";
  severity: "dangerous" | "suspicious" | "unusual";
  was_blocked: boolean;
}
```

### Detection Patterns

The kill chain detector scans the event buffer for these sequences, all from the same server within a 60-second window:

| Pattern Name | Step 1 | Step 2 | Step 3 (optional) | Verdict Template |
|---|---|---|---|---|
| `credential_exfiltration` | Sensitive file read (SSH/AWS/env) | Network connection | -- | `{server} read a credentials file and then tried to send data externally. I blocked the chain.` |
| `recon_credential_access` | Discovery request OR multiple directory listings (3+) | Sensitive file read | -- | `{server} scanned your files then went for credentials. I blocked it.` |
| `data_staging_exfiltration` | File write to /tmp or temp directory | Network connection | -- | `{server} staged data in a temporary location and tried to send it out. I blocked the connection.` |
| `privilege_escalation` | File read of system config | File write to system directory (/usr/local/bin, /etc) | -- | `{server} tried to escalate privileges by modifying system files. I blocked the write.` |
| `recon_exec_exfiltration` | Discovery request | Shell command execution | Network connection | `{server} discovered available tools, executed commands, and tried to contact an external server. I blocked the chain.` |

**Detection algorithm**:
1. On each new event, check if this server has recent events in the buffer (last 60s).
2. For each pattern, check if the accumulated events from this server match the step sequence.
3. If a match is found, create a `KillChainNarrative` and emit it.
4. Mark all constituent events with the `kill_chain_id`.

---

## 9. Weekly Digest Model

```rust
// src-tauri/src/digest.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyDigest {
    pub id: String,
    pub period_start: String,
    pub period_end: String,
    pub generated_at: String,

    /// Human-readable summary paragraph
    pub summary_text: String,

    /// Stats
    pub stats: DigestStats,

    /// Top 3 notable events of the week
    pub highlights: Vec<DigestHighlight>,

    /// Actionable recommendations
    pub recommendations: Vec<DigestRecommendation>,

    /// Protection score trend
    pub protection_score_trend: ScoreTrend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestStats {
    pub total_events: u64,
    pub events_blocked: u64,
    pub events_prompted: u64,
    pub events_allowed: u64,
    pub servers_monitored: u32,
    pub alerts_generated: u32,
    pub alerts_resolved: u32,
    pub kill_chains_detected: u32,
    pub new_servers_found: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestHighlight {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub event_id: Option<String>,
    pub alert_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestRecommendation {
    pub id: String,
    pub description: String,
    pub action_label: String,
    pub action_route: String,
    pub priority: String,       // "high" | "medium" | "low"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreTrend {
    pub current_score: u32,
    pub previous_score: u32,
    pub direction: String,      // "up" | "down" | "stable"
    pub change_reason: Option<String>,
}
```

### TypeScript Interface

```typescript
export interface WeeklyDigest {
  id: string;
  period_start: string;
  period_end: string;
  generated_at: string;
  summary_text: string;
  stats: DigestStats;
  highlights: DigestHighlight[];
  recommendations: DigestRecommendation[];
  protection_score_trend: ScoreTrend;
}

export interface DigestStats {
  total_events: number;
  events_blocked: number;
  events_prompted: number;
  events_allowed: number;
  servers_monitored: number;
  alerts_generated: number;
  alerts_resolved: number;
  kill_chains_detected: number;
  new_servers_found: number;
}

export interface DigestHighlight {
  title: string;
  description: string;
  severity: string;
  event_id: string | null;
  alert_id: string | null;
}

export interface DigestRecommendation {
  id: string;
  description: string;
  action_label: string;
  action_route: string;
  priority: "high" | "medium" | "low";
}

export interface ScoreTrend {
  current_score: number;
  previous_score: number;
  direction: "up" | "down" | "stable";
  change_reason: string | null;
}
```

**Summary text generation**: The digest generates a paragraph in Claw's voice using template interpolation:

> "This week: {total_events} events monitored, {events_blocked} blocked, {events_prompted} required your decision. {servers_monitored} servers are being watched. {top_finding_or_all_clear}."

---

## 10. Recommendation Model

Recommendations are generated from system state analysis. They appear in the Alerts page and the Weekly Digest.

### Recommendation Types

| Type | Trigger | Description Template | Action |
|------|---------|---------------------|--------|
| `frequent_prompts` | Server prompted > 10 times in 24h for same action | `{server} keeps asking about {action}. Add a rule to save yourself the interruptions.` | Route to Policy Editor |
| `unused_restriction` | Block rule has not matched in 30 days | `You have a block rule for {pattern} that has not matched in a month. Still need it?` | Route to Policy Editor |
| `permission_tightening` | Server in "cautious" trust but all actions allowed for 7 days | `{server} has been well-behaved. Consider tightening its permissions now that you know its patterns.` | Route to Tools page |
| `trust_suggestion` | Server in "standard" trust with anomaly < 0.1 for 14 days | `{server} has been completely consistent for 2 weeks. You could upgrade its trust level.` | Route to Tools page |
| `update_suggestion` | Server version outdated per threat feed | `{server} has a newer version available. Updates often include security fixes.` | Route to Scanner |
| `learning_completion` | Server profile transitions from learning to active | `I have learned {server}'s patterns. Behavioral monitoring is now active.` | Informational |
| `unwrapped_server` | Unwrapped server detected for > 3 days | `{server} is still not monitored. I cannot see what it does.` | Route to Tools page |

### Rust Struct

```rust
// src-tauri/src/recommendations.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub rec_type: String,
    pub description: String,
    pub action_label: String,
    pub action_route: String,
    pub priority: String,           // "high" | "medium" | "low"
    pub server_name: Option<String>,
    pub created_at: String,
    pub dismissed: bool,
}
```

---

## 11. Correlation Model

Since no correlation engine crate exists, correlation is implemented by matching events by server + timing in the event buffer.

### CorrelationResult Struct

```rust
// src-tauri/src/correlation.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// The anchor event being correlated
    pub anchor_event_id: String,
    /// Events from the same server within the correlation window
    pub correlated_events: Vec<CorrelatedEvent>,
    /// Coverage assessment
    pub coverage: CoverageAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    pub event_id: String,
    pub timestamp: String,
    pub relationship: String,       // "same_server" | "same_tool" | "same_resource" | "temporal"
    pub time_delta_ms: i64,         // Milliseconds from anchor event
    pub humanized_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAssessment {
    /// Percentage of events from this server that are correlated to MCP requests
    pub correlation_percentage: f32,
    /// Number of uncorrelated events
    pub uncorrelated_count: u32,
    /// Human-readable summary
    pub summary: String,
    /// e.g. "All activity from this server matches MCP requests" or "3 events could not be traced to MCP requests"
}
```

### TypeScript Interfaces

```typescript
export interface CorrelationResult {
  anchor_event_id: string;
  correlated_events: CorrelatedEvent[];
  coverage: CoverageAssessment;
}

export interface CorrelatedEvent {
  event_id: string;
  timestamp: string;
  relationship: "same_server" | "same_tool" | "same_resource" | "temporal";
  time_delta_ms: number;
  humanized_description: string;
}

export interface CoverageAssessment {
  correlation_percentage: number;
  uncorrelated_count: number;
  summary: string;
}
```

### Correlation Algorithm

1. Given an anchor event, find all events from the same `server_name` within a 60-second window.
2. Classify relationships:
   - `same_tool`: Same `tool_name`
   - `same_resource`: Same or overlapping `resource` path
   - `temporal`: Same server, different tool/resource, within 60s
3. Compute coverage: what percentage of events from this server in this time window can be correlated to MCP tool calls.
4. Events with `event_type` other than `proxy` or `mcp-proxy` that cannot be matched are flagged as uncorrelated.

---

## 12. New Rust Module Registry

All new modules go in `clients/clawdefender-app/src-tauri/src/`. Register in `lib.rs`.

| Module File | Purpose | Tauri Commands |
|-------------|---------|----------------|
| `humanizer.rs` | Event enrichment and humanization pipeline | `get_humanized_events`, `get_humanized_event` |
| `alert_engine.rs` | Alert promotion, dedup, lifecycle management | `get_intelligent_alerts`, `resolve_alert`, `dismiss_alert`, `review_alert` |
| `kill_chain.rs` | Kill chain detection and narrative generation | `get_kill_chain_narrative` |
| `notification_router.rs` | Notification channel routing and suppression | (internal, called by event_stream.rs) |
| `digest.rs` | Weekly digest generation | `get_weekly_digest`, `get_latest_digest` |
| `recommendations.rs` | Recommendation generation from system state | `get_recommendations`, `dismiss_recommendation` |
| `correlation.rs` | Event correlation and coverage assessment | `get_correlation`, `get_coverage_assessment` |

### lib.rs Registration

```rust
mod humanizer;
mod alert_engine;
mod kill_chain;
mod notification_router;
mod digest;
mod recommendations;
mod correlation;
```

All new commands must be added to the `.invoke_handler(tauri::generate_handler![...])` block in `lib.rs`.

---

## 13. Frontend Store Updates

### humanizedEventStore.ts (new)

```typescript
import { create } from "zustand";
import type { HumanizedEvent } from "../types";

const MAX_EVENTS = 10_000;

interface HumanizedEventStore {
  events: HumanizedEvent[];
  addEvent: (event: HumanizedEvent) => void;
  setEvents: (events: HumanizedEvent[]) => void;
}
```

### intelligentAlertStore.ts (new, replaces alertStore.ts)

```typescript
import { create } from "zustand";
import type { IntelligentAlert } from "../types";

interface IntelligentAlertStore {
  alerts: IntelligentAlert[];
  unresolvedCount: number;
  addAlert: (alert: IntelligentAlert) => void;
  resolveAlert: (id: string) => void;
  dismissAlert: (id: string) => void;
  reviewAlert: (id: string) => void;
  setAlerts: (alerts: IntelligentAlert[]) => void;
}
```

### digestStore.ts (new)

```typescript
import { create } from "zustand";
import type { WeeklyDigest } from "../types";

interface DigestStore {
  latestDigest: WeeklyDigest | null;
  setDigest: (digest: WeeklyDigest) => void;
}
```

---

## 14. New Tauri Events

| Event Name | Payload Type | Emitted When |
|------------|-------------|-------------|
| `clawdefender://humanized-event` | `HumanizedEvent` | New event processed through humanization pipeline |
| `clawdefender://intelligent-alert` | `IntelligentAlert` | Alert promoted from event |
| `clawdefender://kill-chain` | `KillChainNarrative` | Kill chain detected |
| `clawdefender://digest-ready` | `WeeklyDigest` | Weekly digest generated |
| `clawdefender://recommendation` | `Recommendation` | New recommendation generated |

These supplement the existing events (`clawdefender://event`, `clawdefender://prompt`, `clawdefender://auto-block`, `clawdefender://alert`). The old events are kept for backward compatibility during migration.

---

## 15. New Messages for constants/messages.ts

All new user-facing strings from the humanization templates must be added to `src/constants/messages.ts`. The existing `NOTIFICATION_TEMPLATES` object already covers most scenarios. New additions:

```typescript
export const HUMANIZATION_TEMPLATES = {
  // Behavioral context templates
  behavioralLearning: "I am still learning this server's patterns. {eventsNeeded} more events until baseline.",
  behavioralFirstTime: "First time this server has done this.",
  behavioralRare: "This server has done this {count} time(s) before.",
  behavioralRegular: "This happens regularly -- about {rate} times per session.",
  behavioralRoutine: "This is routine -- about {dailyRate} times per day.",
  behavioralUnusual: "This server's recent behavior has been unusual. I am watching it more closely.",
  behavioralConsistent: "This server's behavior has been completely consistent.",

  // Risk explanation templates
  riskSensitiveFile: "This targets a sensitive credential file.",
  riskDangerousCommand: "This command pattern is associated with remote code execution or destructive operations.",
  riskUnknownNetwork: "Unknown destination not in any allowlist.",
  riskIoC: "This destination matches known malicious infrastructure.",
  riskKillChain: "Multi-step attack pattern detected.",
  riskNormal: "No specific risk pattern matched.",
  riskOutOfTerritory: "Access outside learned territory boundaries.",
  riskRateSpike: "Activity rate exceeds 3x normal baseline.",

  // Kill chain verdicts
  killChainCredentialExfiltration: "{server} read a credentials file and then tried to send data externally. I blocked the chain.",
  killChainReconCredential: "{server} scanned your files then went for credentials. I blocked it.",
  killChainDataStaging: "{server} staged data in a temporary location and tried to send it out. I blocked the connection.",
  killChainPrivilegeEscalation: "{server} tried to escalate privileges by modifying system files. I blocked the write.",
  killChainReconExec: "{server} discovered tools, executed commands, and tried to contact an external server. I blocked the chain.",

  // Digest
  digestSummary: "This week: {totalEvents} events monitored, {blockedCount} blocked, {promptedCount} required your decision. {serversMonitored} servers are being watched. {topFindingOrAllClear}.",
  digestAllClear: "No threats detected this week. Everything ran smoothly.",
} as const;
```

---

## 16. Design Constraints Checklist

- [x] All new Rust modules in `src-tauri/src/`, NOT in `crates/`
- [x] All modules registered in `lib.rs`
- [x] All commands registered in `invoke_handler`
- [x] Frontend uses Zustand stores
- [x] All colors via CSS variables (`var(--color-*)`)
- [x] All user-facing strings in `constants/messages.ts`
- [x] Claw's voice: calm, observant, direct, honest, warm
- [x] No passive voice in one-liners
- [x] TypeScript interfaces match Rust structs (serde Serialize/Deserialize)
- [x] No anomaly scores, dimension names, or policy syntax shown to user
- [x] Behavioral context computed from available data (event buffer + ServerProfileSummary)
- [x] Kill chain detection from AuditEvent patterns, not from a behavioral engine crate
