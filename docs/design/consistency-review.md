# Rookbot Design System -- Consistency Review

Reviewer: Agent 7 (QA)
Documents reviewed:
- character-brief.md
- voice-guide.md
- threat-communication.md
- visual-identity.md
- onboarding-copy.md
- runtime-messages.md

Issues are categorized as:
- **MUST FIX** -- inconsistency, voice violation, or factual contradiction
- **SHOULD FIX** -- could be clearer, minor drift from voice
- **NITPICK** -- preference, polish

---

## 1. Voice Consistency Check

### 1.1 Messages that sound alarmist when they should be calm

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 1 | **MUST FIX** | voice-guide.md, Section 2.5, Critical/Kill Chain example 3 | "BLOCKED: Coordinated exfiltration attempt across 2 servers." -- Uses ALL CAPS "BLOCKED" as a standalone label. The voice guide's own rule (Section 3, "No ALL CAPS") says one word maximum and only in the most critical alerts. This example is borderline acceptable since it IS a critical alert, but it reads as alarmist compared to the character brief's principle of "the severity comes from the content, not from the formatting." |
| 2 | **SHOULD FIX** | runtime-messages.md, Section 1, High/Critical Risk Example 1 | "Server anomaly score is 0.9" -- The threat-communication.md cardinal rule says "the user never sees anomaly score numbers." This leaks a raw score into the prompt window. |
| 3 | **SHOULD FIX** | runtime-messages.md, Section 1, High/Critical Risk Example 4 | "Anomaly score 0.95" -- Same issue. Raw anomaly score shown to the user. |

### 1.2 Messages using jargon without explanation

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 4 | **MUST FIX** | threat-communication.md, scenario 22 | "CVE" is not explained. The term "vulnerability" is used but "CVE-2026-1847" is raw jargon a non-technical user would not understand. Needs inline explanation on first use (e.g., "a publicly reported security issue, CVE-2026-1847"). |
| 5 | **MUST FIX** | runtime-messages.md, Section 1, High/Critical Risk template | "Risk: [Level]" as a label prefix -- The character brief (Section 3, "What Claw NEVER sounds like -- Robotic") explicitly forbids labels like this. "Risk: Critical" reads like a log entry, not a sentence from a friend. |
| 6 | **SHOULD FIX** | onboarding-copy.md, Screen 2 | "MCP servers" used in the framing text: "I scanned your system for AI tools and MCP servers." The character brief establishes that users hear "AI tools" not "MCP servers." This is the first screen after welcome -- the user may not know what MCP means yet. |
| 7 | **SHOULD FIX** | threat-communication.md, scenario 10 | "IoCs" is used in the educational aside without prior definition. The abbreviation "IoC" appears for the first time here. The expanded text explains it, but the term should be introduced before the abbreviation. |
| 8 | **SHOULD FIX** | onboarding-copy.md, Section 3, Protection Score | "SLM not active" -- "SLM" is never explained to the user. The full term "local security model" appears in the description but the heading itself is jargon. |
| 9 | **NITPICK** | threat-communication.md, scenario 14 | "MCP protocol" is used. "MCP" already stands for "Model Context Protocol" so "MCP protocol" is redundant (like "ATM machine"). Should be "the MCP" or "the protocol." |

### 1.3 Messages that are condescending or over-explain

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 10 | **NITPICK** | onboarding-copy.md, Guards empty state | "Guards are automated protections that watch for specific threat patterns -- like prompt injection, credential exfiltration, or privilege escalation. They run in the background and act on your behalf when something matches." -- This is 2 dense sentences loaded with jargon (prompt injection, credential exfiltration, privilege escalation). A non-technical user would glaze over. Consider simplifying to focus on what guards do for the user rather than listing attack types. |

### 1.4 Passive voice where active would be better

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 11 | **MUST FIX** | threat-communication.md, scenario 19, one-liner | "Automatically blocked -- this looked dangerous." -- Passive construction. Should be "I blocked this automatically -- it looked dangerous." Claw always uses "I." |
| 12 | **SHOULD FIX** | threat-communication.md, scenario 20, one-liner | "Got it -- override noted." -- "Override noted" is passive/robotic. Better: "Got it -- I noted your override and I will keep watching." |
| 13 | **SHOULD FIX** | runtime-messages.md, Section 2, toast 7 | "MCP servers cannot write to system directories." -- This reads like a rule statement from a policy engine, not from Claw. Better: "I do not allow MCP servers to write to system directories." |
| 14 | **NITPICK** | threat-communication.md, scenario 28, one-liner | "Scan finished. Found [count] issue(s) to review." -- "Found" is ambiguous about who found them. Better: "Scan finished. I found [count] issue(s) to review." |

### 1.5 Messages too long for notification context

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 15 | **SHOULD FIX** | onboarding-copy.md, Variation A body | 2 long sentences that run together. "I sit between you and the AI tools you use every day -- watching the traffic, catching the threats, keeping your machine safe. Let me take a quick look at what you have running." -- The first sentence alone is 27 words with 3 clauses. The voice guide says max 2 clauses. |
| 16 | **SHOULD FIX** | onboarding-copy.md, Variation B body | "I watch over the AI tools on your machine and make sure they behave. Think of me as a security expert who lives in your menu bar. I will scan your system, set up protection, and stay out of your way. Ready?" -- 4 sentences is fine for an onboarding body, but "Think of me as a security expert who lives in your menu bar" borders on condescending per the character brief. Claw does not explain what it is metaphorically -- it just acts. |

### 1.6 Inconsistent terminology

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 17 | **MUST FIX** | Cross-document | **"blocked" vs "stopped" vs "denied"**: threat-communication.md consistently uses "blocked." But voice-guide.md Section 1.1 uses "stopped" ("I stopped it"). runtime-messages.md toast 7 says "cannot write." The character brief uses "blocked" in most places but "stopped" in one ("I stopped it -- your call"). **Decision needed: always use "blocked" for auto-actions and "stopped" / "paused" for user-prompted pauses?** |
| 18 | **MUST FIX** | Cross-document | **"AI tools" vs "MCP servers" vs "servers" vs "agents"**: The character brief says Claw sits between "you and the AI tools you use." threat-communication.md one-liners use "agent" ("An agent tried to..."), "server" ("Server ran a shell command"), and "this server." onboarding-copy.md says "AI tools." There is no consistent rule for when to say "agent," "server," "AI tool," or "MCP server." |
| 19 | **MUST FIX** | Cross-document | **"paused" vs "blocked"**: threat-communication.md scenarios 1 and 2 use "paused" ("I paused it"). Scenario 5 uses "stopped." Scenario 3 uses "blocked." These are three different words for the same action (intercepted a call and waiting for user decision). |
| 20 | **SHOULD FIX** | Cross-document | **"monitoring" vs "protecting" vs "watching"**: onboarding-copy.md Screen 2 says "protect." The character brief says "watching." The voice guide says "monitoring" ("I am monitoring 3 servers"). Dashboard status says "monitored." These are used interchangeably without a clear rule. |
| 21 | **SHOULD FIX** | Cross-document | **Protection score capitalization**: onboarding-copy.md uses lowercase "protection score" everywhere. runtime-messages.md weekly digest examples use "Protection score:" with a capital P. Pick one. |
| 22 | **SHOULD FIX** | visual-identity.md vs threat-communication.md | **"Unusual" color mismatch**: threat-communication.md maps "Unusual" to Amber `#D97706` with an Eye icon. visual-identity.md maps "Unusual / Info" to Blue with an Eye icon. These are different colors for the same status label. |

### 1.7 Exclamation marks where they do not belong

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 23 | **NITPICK** | runtime-messages.md, Section 4, "First threat blocked" | "This is exactly what I am here for." -- No exclamation mark, good. But the tone is slightly self-congratulatory. The character brief says "Claw does not celebrate." This leans toward celebration. |

### 1.8 Messages that say "Error" or "Warning" as standalone labels

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 24 | **MUST FIX** | runtime-messages.md, Section 5, all error messages | Each error starts with a bold sentence that acts as a label-like headline: "**Claw's daemon is not running.**", "**The daemon crashed and restarted.**" etc. This is acceptable because they ARE sentences. However, error #1 uses "Claw's daemon" -- Claw refers to itself as "I" in messages. It should be "My daemon is not running" or "I cannot reach the daemon." The possessive "Claw's" is third-person in a first-person context. |
| 25 | **SHOULD FIX** | runtime-messages.md, Section 1, High-Risk template | "Risk: [Level]" as a standalone label on the risk details line. This is exactly the pattern the character brief warns against -- raw labels. It should be woven into a sentence: "This is high risk because..." |

### 1.9 Contraction consistency

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 26 | **NITPICK** | Cross-document | The voice guide says "Use contractions. They keep the voice natural." But the vast majority of messages across all documents use uncontracted forms: "I am," "I will," "I do not," "I have not." This is not wrong (the guide says do not force them), but the overall tone feels more formal than the voice guide's own examples, which use "I'm," "I don't," "It's." Consider adding more contractions to onboarding and conversational messages specifically. |

---

## 2. Terminology Audit

### 2.1 What we call AI tools

| Term | Where Used | Context |
|------|-----------|---------|
| "AI tools" | character-brief.md, onboarding-copy.md | User-facing, general |
| "MCP servers" | threat-communication.md, onboarding-copy.md Screen 2 | Mixed user/developer |
| "servers" | threat-communication.md one-liners, runtime-messages.md | Shorthand in context |
| "agents" | threat-communication.md one-liners (scenarios 1-7, 18) | User-facing |
| "MCP clients" | onboarding-copy.md, runtime-messages.md error 7 | Developer-facing leaked into user copy |

**Recommendation**: "AI tools" for the thing the user interacts with (Cursor, Claude Desktop). "Servers" for the MCP server component (once context is established). "Agents" should be reserved for the guard/agentic AI context only. "MCP servers" and "MCP clients" belong in developer docs only.

### 2.2 What we call protecting

| Term | Where Used |
|------|-----------|
| "monitoring" | voice-guide.md, threat-communication.md, runtime-messages.md digest |
| "protecting" | onboarding-copy.md setup complete ("3 servers protected") |
| "watching" | character-brief.md, visual-identity.md empty states |

**Recommendation**: "monitoring" for the active state (I am monitoring 3 servers). "protected" for the outcome state (3 servers protected). "watching" for conversational/informal use. Document this in the glossary.

### 2.3 What we call blocked events

| Term | Where Used | Meaning |
|------|-----------|---------|
| "blocked" | Most documents | Auto-blocked or user-blocked |
| "paused" | threat-communication.md scenarios 1, 2, 5 | Waiting for user decision |
| "stopped" | voice-guide.md Section 1.1 | Same as paused |
| "denied" | Not used | -- |

**Recommendation**: "blocked" = Claw took final action, the call did not go through. "paused" = Claw intercepted and is waiting for the user to decide. Never use "stopped" or "denied" in user-facing copy.

### 2.4 Risk level labels

| Label | threat-communication.md | visual-identity.md | runtime-messages.md |
|-------|------------------------|--------------------|--------------------|
| Dangerous | Yes (Red) | Yes (Red, ShieldX) | Yes (implied in high-risk prompts) |
| Suspicious | Yes (Orange) | Yes (Amber, AlertTriangle) | Not explicitly labeled |
| Unusual | Yes (Amber) | Yes (Blue, Eye) | Not used |
| Normal | Yes (Green) | Yes (Green, ShieldCheck) | Not used |
| Blocked | Yes (Red) | Yes (Red, Ban) | Yes |
| Info | Yes (Amber) | Not defined as badge | Not used |

**Issue**: "Suspicious" is Orange in threat-communication.md but Amber in visual-identity.md badges. "Unusual" is Amber in threat-communication.md but Blue in visual-identity.md. These need to align. See MUST FIX #22 above.

### 2.5 Protection score naming

| Usage | Document |
|-------|----------|
| "protection score" (lowercase) | onboarding-copy.md |
| "Protection score" (capitalized) | runtime-messages.md weekly digest |
| "Your protection score" | onboarding-copy.md Section 3 |

**Recommendation**: Always lowercase "protection score" unless at the start of a sentence. It is a description, not a brand name.

---

## 3. Completeness Check

### 3.1 Threat communication scenarios

**Required: 30 scenarios. Found: 30.** Complete.

Scenarios 1-30 are all present with internal event, one-liner, expanded explanation, and recommended action. Educational asides are included where appropriate (scenarios 1, 2, 5, 10, 14, 15, 21).

### 3.2 Runtime error states

**Required: 14 error states. Found: 14.** Complete.

Errors 1-14 all have user-facing message, recommended action, and action buttons.

### 3.3 Onboarding empty states

| Empty State | Present? |
|-------------|----------|
| Dashboard -- No Events | Yes |
| Activity Feed -- No Events | Yes |
| Alerts -- No Threats | Yes |
| My Tools -- No Servers | Yes |
| Scanner -- No History | Yes |
| Guards -- No Active Guards | Yes |
| Ask Claw -- No History | **MISSING** |
| Settings -- first visit | **MISSING** |

**SHOULD FIX**: Two empty states appear to be missing. "Ask Claw" with no conversation history needs a prompt/suggestion state. Settings first-visit may not need an empty state but could benefit from a one-liner ("Here are your defaults. I picked sensible ones -- adjust anything that does not fit.").

### 3.4 Visual identity component guide gaps

| Component | Defined? | Notes |
|-----------|----------|-------|
| Buttons (4 variants) | Yes | Primary, Secondary, Danger, Ghost |
| Badges/Pills (6 types) | Yes | All status levels |
| Toggle switches | Yes | |
| Input fields | Yes | |
| Cards (4 types) | Yes | Standard, Alert, Stat, Server |
| Progress indicators | Yes | Determinate + indeterminate |
| Empty states | Yes | Pattern defined |
| Prompt window | **Partial** | Animation defined, but no full component spec (layout, sizing, button placement) |
| Toast notifications | **Partial** | Animation defined, but no component spec for content layout |
| Banner notifications | **MISSING** | Referenced in threat-communication.md Tier 2, but no visual spec |
| Modal/Dialog | **MISSING** | No generic modal/dialog component spec |
| Sidebar navigation | **Partial** | Icons listed, width defined, but no full component spec (active state, hover, collapsed) |
| Tooltip | **MISSING** | No tooltip component defined |
| Table/Data grid | **MISSING** | Activity log and event lists need a table component spec |

**SHOULD FIX**: Banner notification, modal/dialog, tooltip, and table components are used in the product but not specified in visual-identity.md.

---

## 4. Persona Check

### Developer Persona

Developers need to drill into technical detail. Checking each document:

| Document | Developer OK? | Issue |
|----------|--------------|-------|
| threat-communication.md | Yes | Expandable explanations give enough detail. Internal events documented for dev reference. |
| runtime-messages.md prompts | **Partial** | High-risk prompts show "Risk: Critical" but no way to see the raw event data, tool call payload, or server logs from the prompt window. Developers would want a "View raw event" link. |
| runtime-messages.md errors | Yes | "View crash log" and "Learn more" provide drill-down. |
| onboarding-copy.md | Yes | Minimal technical detail is appropriate for onboarding. |

**SHOULD FIX**: Add a "View raw event" or "Technical details" expandable section to the high-risk prompt template for developer users.

### Non-Technical Parent Persona

A non-technical user who wants to keep their machine safe. Would they understand? Would they be scared or reassured?

| Document | Parent OK? | Issue |
|----------|-----------|-------|
| threat-communication.md | **Partial** | Most one-liners are clear. However, terms like "kill chain," "IoC," "anomaly score," and "process tree" appear without plain-language alternatives in the one-liners. One-liners should never assume security knowledge. |
| runtime-messages.md prompts | **Partial** | Low-risk prompts are excellent -- clear action, clear context. High-risk prompts are good but the "Risk: Critical" label is intimidating without being helpful. A parent would not know what "Critical" means in security context vs. "High." |
| runtime-messages.md errors | Yes | Error messages explain what happened and what to do. Good. |
| onboarding-copy.md | Yes | Warm and approachable. The protection level choices (Keep Watch / Stay Sharp / Lock It Down) are excellent -- a parent could choose without understanding security. |
| runtime-messages.md conversational | Yes | Excellent. "Am I safe right now?" is exactly what a non-technical user would ask, and the answer is reassuring and clear. |

**SHOULD FIX**: Ensure one-liners in threat-communication.md never use security jargon. "Kill chain detected" (scenario 11 one-liner) means nothing to a non-technical user. Rephrase to: "I detected a multi-step attack and stopped it."

---

## 5. Summary

| Category | MUST FIX | SHOULD FIX | NITPICK |
|----------|----------|------------|---------|
| Voice consistency | 4 | 5 | 4 |
| Terminology | 3 | 3 | 0 |
| Completeness | 0 | 3 | 0 |
| Persona | 0 | 2 | 0 |
| **Total** | **7** | **13** | **4** |

### Top 3 Priorities

1. **Standardize action verbs** (MUST FIX #17, #19): Pick "blocked" for final actions and "paused" for awaiting-decision states. Apply everywhere.
2. **Standardize entity naming** (MUST FIX #18): Define when to use "AI tool," "server," and "agent." Never use "MCP server" or "MCP client" in user-facing copy.
3. **Remove raw scores from user-facing copy** (SHOULD FIX #2, #3): runtime-messages.md leaks anomaly scores into prompt windows, violating threat-communication.md's cardinal rule.
