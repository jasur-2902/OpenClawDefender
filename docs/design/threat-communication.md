# ClawDefender Threat Communication Guide

This document defines how ClawDefender translates internal security signals into user-facing language. Every message follows the voice defined in the [Character Brief](character-brief.md): calm, direct, honest, warm, and never alarmist.

The cardinal rule: **the user never sees anomaly score numbers, dimension names, kill chain pattern IDs, or policy rule syntax.** Internal metrics are translated into plain language and visual cues before they reach the screen.

---

## Section 1 -- Threat Level Mapping

### Master Translation Table

| Internal Signal | Score / Condition | User-Facing Label | Color | Icon | Example One-Liner | Notification Type |
|---|---|---|---|---|---|---|
| Anomaly score 0.9+ | `score >= 0.9` | **Dangerous** | Red `#DC2626` | Shield with X | "I blocked this -- it matches a known attack pattern." | Full prompt window + sound |
| Anomaly score 0.7--0.9 | `0.7 <= score < 0.9` | **Suspicious** | Orange `#EA580C` | Warning triangle | "This looks off. Worth checking before it continues." | Full prompt window |
| Anomaly score 0.4--0.7 | `0.4 <= score < 0.7` | **Unusual** | Amber `#D97706` | Eye | "New behavior from this server. I am keeping an eye on it." | Banner notification |
| Anomaly score 0.0--0.4 | `score < 0.4` | **Normal** | Green `#16A34A` | Checkmark | "All clear." | In-feed only |
| Kill chain detected | Any pattern match | **Dangerous** | Red `#DC2626` | Chain link | "I detected a multi-step attack pattern and shut it down." | Full prompt window + sound |
| Auto-blocked | DecisionEngine auto-block | **Blocked** | Red `#DC2626` | Shield | "Blocked automatically. Tap to review." | Toast (auto-dismiss) |
| IoC match | Threat intel match | **Dangerous** | Red `#DC2626` | Skull | "This matches a known threat. Blocked." | Full prompt window + sound |
| SLM mock mode | Mock backend active | **Info** | Amber `#D97706` | Info circle | "Local AI analysis is running in demo mode. Results are advisory only." | Banner notification |

### Label Definitions (Internal Reference)

- **Dangerous**: Requires immediate user attention or was auto-blocked. Maps to behavioral auto-block threshold, kill chain detection, or IoC match.
- **Suspicious**: High confidence that something is wrong but not definitively malicious. User decision required.
- **Unusual**: Behavioral deviation from learned baseline. Logged and surfaced but does not block.
- **Normal**: Within learned behavioral baseline. Logged silently.
- **Blocked**: System took automatic action. User can review and override.
- **Info**: System status messages, mock mode notices, educational context.

---

## Section 2 -- Message Templates

Each scenario includes four elements:
1. **Internal event** -- developer reference only, never shown to user
2. **One-liner** -- notification and feed text
3. **Expanded explanation** -- detail view when user taps/clicks
4. **Recommended action** -- what the user can do

An optional **Educational aside** is included where it helps the user understand why something matters.

---

### 1. Agent trying to read SSH keys

**Internal event**: `OsEventKind::Open` on `~/.ssh/id_rsa` correlated with MCP `tools/call`, anomaly dimension `SensitiveTarget`

**One-liner**: "A server tried to read your SSH private key. I paused it."

**Expanded**: "The server `{server_name}` made a tool call that attempted to open `~/.ssh/id_rsa`. SSH private keys grant access to remote servers, so I paused this and I am asking you before it goes further."

**Action**: Allow Once / Allow for Session / Block / Add Policy Rule

**Educational**: "SSH keys are like master passwords to your servers. A legitimate server rarely needs to read the private key itself."

---

### 2. Agent trying to read AWS credentials

**Internal event**: `OsEventKind::Open` on `~/.aws/credentials`, dimension `SensitiveTarget`

**One-liner**: "A server tried to access your AWS credentials. I paused it."

**Expanded**: "The server `{server_name}` attempted to read your AWS credentials file. This file contains secret keys that could give access to your cloud infrastructure."

**Action**: Allow Once / Allow for Session / Block / Add Policy Rule

**Educational**: "If a server needs AWS access, it is safer to use environment variables with limited-scope IAM roles than to expose your credentials file."

---

### 3. Agent trying to read browser cookies/passwords

**Internal event**: `OsEventKind::Open` on browser profile paths (Chrome, Firefox, Safari cookie/login databases), dimension `SensitiveTarget`

**One-liner**: "A server tried to access your browser passwords. I blocked it."

**Expanded**: "The server `{server_name}` attempted to read a browser password or cookie database. There is no legitimate reason for an MCP server to access browser credentials. I blocked this automatically."

**Action**: Review Details / Trust This Server (override)

---

### 4. Agent executing low-risk shell command

**Internal event**: `tools/call` with shell execution, command matches low-risk pattern (`ls`, `pwd`, `echo`, `cat`, `which`), anomaly score < 0.4

**One-liner**: "Server ran a shell command: `ls ./src`"

**Expanded**: "The server `{server_name}` executed `ls ./src` in your project directory. This is a routine file listing command within the expected working area."

**Action**: No action needed (in-feed only)

---

### 5. Agent executing high-risk shell command

**Internal event**: `tools/call` with shell execution matching high-risk pattern (`curl | bash`, `rm -rf`, `chmod 777`, `wget -O- | sh`), anomaly score 0.7+

**One-liner**: "A server tried to run a dangerous shell command. I paused it."

**Expanded**: "The server `{server_name}` attempted to execute `{command_summary}`. This type of command can download and run arbitrary code or permanently delete files. I paused it for your review."

**Action**: Allow Once / Block / View Full Command

**Educational**: "Piping a download directly into a shell (`curl | bash`) runs whatever code is on the other end with no review. It is one of the most common ways malicious code gets executed."

---

### 6. Agent accessing file outside project directory (first time)

**Internal event**: `OsEventKind::Open` on path outside project root, dimension `UnknownPath`, first occurrence

**One-liner**: "A server accessed a file outside your project for the first time."

**Expanded**: "The server `{server_name}` read `{file_path}`, which is outside your current project directory. This is the first time this server has reached outside the project. It might be a normal config lookup, but I wanted you to know."

**Action**: Looks Fine / Watch This Server / Block Path

---

### 7. Agent accessing file outside project directory (repeated)

**Internal event**: `OsEventKind::Open` on path outside project root, repeated pattern, elevated anomaly from rate

**One-liner**: "This server keeps accessing files outside your project."

**Expanded**: "The server `{server_name}` has now accessed `{count}` files outside your project directory. The most recent was `{file_path}`. Repeated external file access can indicate data collection behavior."

**Action**: Review All Accessed Paths / Restrict to Project / Block Server

---

### 8. Agent network connection to known API

**Internal event**: `OsEventKind::Connect` to recognized API endpoint (e.g., `api.anthropic.com`, `api.openai.com`), DNS allowlist match

**One-liner**: "Server connected to `api.anthropic.com`. Expected."

**Expanded**: "The server `{server_name}` made a network connection to `api.anthropic.com`, which is a recognized AI provider API. This is normal behavior for this type of server."

**Action**: No action needed (in-feed only)

---

### 9. Agent network connection to unknown external IP

**Internal event**: `OsEventKind::Connect` to IP not in allowlist, no IoC match, dimension `UnknownNetwork`

**One-liner**: "A server connected to an unfamiliar address."

**Expanded**: "The server `{server_name}` connected to `{ip_address}:{port}`. I do not recognize this destination, and it is not in any allowlist. It could be legitimate, but I have not seen this server connect here before."

**Action**: Allow / Block This Address / Investigate

---

### 10. Agent network connection to known malicious IP (IoC match)

**Internal event**: `OsEventKind::Connect` to IP matching IoC database, threat intel match

**One-liner**: "A server tried to contact a known malicious host. I blocked it."

**Expanded**: "The server `{server_name}` attempted to connect to `{ip_address}`, which is flagged in threat intelligence feeds as malicious. I blocked the connection. This could indicate a compromised MCP server."

**Action**: Review Threat Details / Block Server Permanently / Report

**Educational**: "Indicators of Compromise (IoCs) are addresses, file hashes, and patterns that have been observed in real-world attacks and shared by the security community."

---

### 11. Kill chain: credential read then network connection

**Internal event**: KillChainDetector match on `credential_theft_exfiltration` pattern -- `SensitiveTarget` followed by `Connect`

**One-liner**: "I detected a credential theft pattern and blocked it."

**Expanded**: "The server `{server_name}` first read a credentials file, then immediately tried to make a network connection. This sequence matches a known credential exfiltration attack. I blocked the network connection and logged everything."

**Action**: Review Full Chain / Block Server / View Audit Log

---

### 12. Kill chain: reconnaissance then credential access

**Internal event**: KillChainDetector match on `recon_credential_access` -- directory listing/enumeration followed by credential file access

**One-liner**: "A server scanned your files then went for credentials. I blocked it."

**Expanded**: "The server `{server_name}` first listed files across multiple directories, then targeted a sensitive credentials file. This pattern -- looking around first, then going for the valuables -- matches a known reconnaissance-to-theft attack chain. Blocked."

**Action**: Review Full Chain / Block Server / View Audit Log

---

### 13. Kill chain: file staging then exfiltration attempt

**Internal event**: KillChainDetector match on `data_staging_exfiltration` -- file copy/write to temp then network connect

**One-liner**: "A server staged files and tried to send them out. I blocked it."

**Expanded**: "The server `{server_name}` copied data to a temporary location, then attempted an outbound network connection. This matches a data exfiltration pattern where files are gathered before being sent externally. I blocked the outbound connection."

**Action**: Review Staged Files / Block Server / View Audit Log

---

### 14. Uncorrelated OS activity

**Internal event**: Correlation engine found `OsEventKind` with no matching MCP request in sliding window, severity based on event type (connect=Critical, exec=High)

**One-liner**: "I noticed system activity that does not match any server request."

**Expanded**: "A `{event_type}` event occurred on your system (`{details}`) that I cannot trace back to any MCP tool call or resource read. This could be normal background activity, or it could be a process acting on its own outside the MCP protocol."

**Action**: Investigate / Dismiss / Add to Baseline

**Educational**: "MCP servers should do their work through the protocol. Activity that happens outside the protocol could mean a server is doing things behind the scenes."

---

### 15. Prompt injection detected in sampling/createMessage

**Internal event**: InjectionDetector triggered on `sampling/createMessage` content, pattern match (instruction override, role reassignment, data exfiltration, etc.)

**One-liner**: "I found a prompt injection attempt in a message to your AI."

**Expanded**: "The server `{server_name}` sent a `sampling/createMessage` request containing text that looks like a prompt injection attack. The suspicious content attempts to `{injection_type}`. I blocked the message."

**Action**: View Suspicious Content / Block Server / Allow (override)

**Educational**: "Prompt injection is when hidden instructions are smuggled into AI inputs, trying to override the AI's original instructions. It is one of the most common attack vectors for AI agents."

---

### 16. Behavioral anomaly: tool never used before

**Internal event**: AnomalyScorer dimension `UnknownTool`, tool not in learned profile for this server

**One-liner**: "This server just used a tool it has never used before."

**Expanded**: "The server `{server_name}` called the tool `{tool_name}` for the first time. Based on its learned behavior profile, this tool has not been part of its normal operation. This could be a new workflow or something unexpected."

**Action**: Looks Fine / Watch This Tool / Block Tool

---

### 17. Behavioral anomaly: first network access by offline server

**Internal event**: AnomalyScorer dimension `FirstNetworkAccess`, server profile has zero prior network events

**One-liner**: "A server that has never gone online just tried to connect to the internet."

**Expanded**: "The server `{server_name}` has never made a network connection in its entire history with me. It just tried to connect to `{destination}`. A server suddenly going online when it has always worked offline is worth attention."

**Action**: Allow / Block Connection / Investigate

---

### 18. Behavioral anomaly: access rate spike

**Internal event**: AnomalyScorer dimension `AbnormalRate`, current rate exceeds 3x learned mean

**One-liner**: "A server is working much faster than normal."

**Expanded**: "The server `{server_name}` is making requests at `{rate_description}` its usual pace. A sudden spike in activity can indicate automated behavior or a compromised server running through a scripted attack sequence."

**Action**: Watch / Throttle / Block Server

---

### 19. Auto-block triggered

**Internal event**: DecisionEngine returned `AutoBlock`, anomaly score >= 0.9 with auto-blocking enabled

**One-liner**: "I blocked this automatically -- it looked dangerous."

**Expanded**: "I blocked an action by `{server_name}` automatically because it combined multiple high-risk signals. Auto-blocking is enabled in your settings and activates when the risk level is very high. You can review this decision and override it."

**Action**: Review Details / Trust This Action / Keep Blocked

---

### 20. Auto-block overridden by user

**Internal event**: User selected "Trust" or "Allow" on auto-blocked event, override rate tracker updated

**One-liner**: "Got it -- override noted. I will keep watching."

**Expanded**: "You chose to allow this action that I blocked automatically. I have logged your decision and will factor it into future assessments. I am still monitoring this server."

**Action**: No action needed (confirmation)

---

### 21. New MCP server detected, not yet wrapped

**Internal event**: Scanner or daemon detected MCP server configuration not routed through proxy

**One-liner**: "I found a new MCP server that I am not monitoring yet."

**Expanded**: "The server `{server_name}` is configured in `{client_name}` but is not routed through my proxy. I cannot see what it does until it is wrapped. I recommend wrapping it so I can monitor its behavior."

**Action**: Wrap This Server / Ignore / View Details

**Educational**: "Wrapping an MCP server means routing its traffic through me. I can then see every tool call and resource read, and block anything suspicious."

---

### 22. Wrapped server has known vulnerability

**Internal event**: Scanner module or threat feed detected vulnerability in server package/version

**One-liner**: "A server you use has a known security issue."

**Expanded**: "The server `{server_name}` (version `{version}`) has a known vulnerability -- a publicly reported security issue (CVE-`{cve_id}`): `{vulnerability_summary}`. This does not mean you are being attacked right now, but it means this server has a weakness that could be exploited."

**Action**: View Details / Update Server / Unwrap and Block

---

### 23. Server matches malicious blocklist entry

**Internal event**: Threat intel blocklist match on server name, hash, or version range

**One-liner**: "This server is on the blocklist. Blocked."

**Expanded**: "The server `{server_name}` matches an entry in the threat intelligence blocklist. It has been identified as malicious by the security community. I blocked it from running."

**Action**: View Blocklist Entry / Override (requires confirmation) / Remove Server

---

### 24. SLM analysis returned HIGH risk

**Internal event**: SLM (local AI model) returned `RiskLevel::High` for event

**One-liner**: "My local AI flagged this as high risk."

**Expanded**: "I ran this event through local AI analysis and it returned a high-risk assessment: `{slm_summary}`. Local analysis is a second opinion alongside behavioral scoring. Together, they suggest this event needs your attention."

**Action**: Review Event / Allow / Block

---

### 25. Swarm analysis returned CRITICAL with specialist breakdown

**Internal event**: Swarm Commander synthesized CRITICAL from specialist agents (Hawk, Forensics, Internal Affairs)

**One-liner**: "Deep analysis confirms this is critical. Three specialists agree."

**Expanded**: "I escalated this event to cloud-based specialist analysis. The threat assessment specialist, forensic analyst, and internal auditor all contributed. Their combined verdict is critical risk: `{swarm_summary}`. This is the highest confidence assessment I can provide."

**Action**: Review Full Analysis / Block Server / View Specialist Reports

---

### 26. Guard activated by agent

**Internal event**: Guard registration via REST API, guard enters Enforce or Monitor mode

**One-liner**: "A guard is now active for `{agent_name}`."

**Expanded**: "The agent `{agent_name}` has activated a security guard in `{mode}` mode. The guard will `{mode_description}` actions taken by this agent against its defined policy."

**Action**: View Guard Policy / Adjust Mode / Deactivate

---

### 27. Guard blocked action from protected agent

**Internal event**: Guard policy evaluation returned Block for agent action

**One-liner**: "Guard blocked `{agent_name}` from `{action_summary}`."

**Expanded**: "The guard protecting `{agent_name}` intercepted and blocked an action: `{action_detail}`. The action violated the guard's policy. The agent was notified that the action was blocked."

**Action**: Review Details / Allow This Action / Adjust Guard Policy

---

### 28. Scan completed with findings

**Internal event**: Scanner finished with one or more findings across modules (path_traversal, prompt_injection, exfiltration, capability_escalation, dependency_audit, fuzzing)

**One-liner**: "Scan finished. Found `{count}` issue(s) to review."

**Expanded**: "I scanned `{server_name}` and found `{count}` potential security issues across `{modules_with_findings}`. The most serious is: `{top_finding_summary}`. Review the full report for details and recommended fixes."

**Action**: View Full Report / Apply Fixes / Rescan

---

### 29. Scan completed clean

**Internal event**: Scanner finished with zero findings

**One-liner**: "Scan complete. No issues found."

**Expanded**: "I scanned `{server_name}` across all security modules and found nothing concerning. This is a good sign, but remember that scans are point-in-time checks. I will keep monitoring continuously."

**Action**: View Report / Schedule Next Scan

---

### 30. Weekly digest summary

**Internal event**: Scheduled weekly aggregation of events, blocks, and status

**One-liner**: "Your weekly security summary is ready."

**Expanded**: "This week: `{total_events}` events monitored, `{blocked_count}` blocked, `{prompted_count}` required your decision. `{servers_monitored}` servers are being watched. `{top_finding_or_all_clear}`. Full details in the audit log."

**Action**: View Full Digest / Open Audit Log

---

## Section 3 -- Notification Priority Rules

The system decides notification priority. Users do not configure these tiers -- they are automatic based on event severity and type.

### Tier 1: Full Prompt Window + Sound

**When**: The event requires a user decision AND involves medium or higher risk, OR matches a specific high-priority pattern.

**Triggers**:
- Kill chain detection (any pattern)
- IoC match (any indicator type)
- Prompt injection detected
- Anomaly score 0.7+ requiring user decision (policy action = Prompt)
- SLM returned HIGH or CRITICAL risk on a prompted event
- Swarm returned CRITICAL
- Server matches blocklist entry (if not auto-blocked)
- First-time credential file access by any server

**Behavior**: A dedicated window appears with event details, analysis, and decision buttons. A short alert sound plays once. The window stays until the user acts or the auto-deny timeout fires.

**Auto-deny timeout**: Events in this tier auto-deny after the configured timeout (default 60 seconds) if the user does not respond. This is fail-closed behavior.

---

### Tier 2: Banner Notification

**When**: The event is worth seeing but does not require an immediate decision.

**Triggers**:
- Anomaly score 0.4--0.7 (Unusual) with policy action Log
- Behavioral anomaly: first use of a new tool
- Behavioral anomaly: first network access by previously offline server
- SLM mock mode notice (shown once per session)
- New unwrapped server detected
- Server vulnerability discovered
- Guard activated or mode changed
- Scan completed with findings

**Behavior**: A banner slides in from the top of the screen. It persists for 8 seconds, then fades. Clicking the banner opens the detail view. Banners stack if multiple arrive within a short window (max 3 visible).

---

### Tier 3: Toast (Auto-Dismiss)

**When**: The system took automatic action and the user should know, but no decision is needed.

**Triggers**:
- Auto-block triggered (score 0.9+ with auto-blocking enabled)
- Auto-block overridden by user (confirmation)
- Guard blocked an action in Enforce mode
- DNS filter blocked a domain
- Network policy blocked a connection (non-IoC)

**Behavior**: A small toast appears in the corner of the screen for 4 seconds, then auto-dismisses. Toasts are brief: one line of text plus the label badge. Tapping opens the detail view. Toasts do not play sound.

---

### Tier 4: In-Feed Only

**When**: The event is routine and low-risk. The user can see it if they look at the timeline, but it does not interrupt them.

**Triggers**:
- Anomaly score < 0.4 (Normal) with policy action Allow or Log
- Low-risk shell commands (ls, pwd, echo, cat)
- Network connections to recognized APIs
- Tool calls within learned behavioral baseline
- Scan completed clean
- Weekly digest (also appears as banner on first view)
- Guard action in Monitor mode (observed, not blocked)

**Behavior**: The event appears in the Timeline feed with its label badge and one-liner. No notification, no sound, no interruption. The dashboard event counter increments.

---

### Tier 5: Silent (Logged Only)

**When**: The event is completely routine and does not need to appear in the feed at all. It exists in the audit log for forensic purposes.

**Triggers**:
- MCP protocol handshake (`initialize`, `initialized`, `ping`)
- Notification messages (`notifications/*`)
- Tool and resource list requests (`tools/list`, `resources/list`, `prompts/list`)
- Events from learning phase (insufficient baseline data, not yet scoring)
- Sensor heartbeat and status events
- Events filtered by the noise filter (compiler, package manager, IDE, git, test runner profiles)

**Behavior**: Written to `audit.jsonl` only. Not shown in Timeline, not counted in dashboard event counter, no notification of any kind. Available through the Audit Log page with "show all" filter.

---

## Appendix: Writing Guide for New Scenarios

When adding new message templates, follow these rules:

1. **Start with what happened, then what Claw did, then what the user can do.** Never start with "WARNING" or "ALERT."
2. **Name the server.** Always include `{server_name}` so the user knows who did it.
3. **Be specific.** "Tried to read your SSH key" not "Attempted sensitive file access."
4. **Use "I" not "we."** Claw is one entity, not a team.
5. **Never show raw scores, IDs, or rule syntax.** Translate everything.
6. **Match severity to language.** "Looks unusual" for Unusual. "This is dangerous" for Dangerous. Do not use dramatic language for low-severity events.
7. **Keep one-liners under 80 characters when possible.** Detail belongs in the expanded view.
8. **Every expanded explanation should answer: what happened, why it matters, and what was done about it.**
9. **Educational asides are optional and brief.** One or two sentences. They explain the "why" for users who want to learn, without being condescending.
10. **Actions are verbs.** "Review Details" not "Details." "Block Server" not "Server Block."
