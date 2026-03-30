# ClawDefender Glossary

Single source of truth for every user-facing term. If a term is not in this glossary, it should not appear in user-facing copy without being added here first.

---

## Product and Identity

| Term | Definition | Usage Notes |
|------|-----------|-------------|
| **Claw** | The personality and voice of ClawDefender. Claw speaks as "I" in all user-facing messages. | Use "Claw" in third-person contexts (settings descriptions, documentation). Never "we." |
| **ClawDefender** | The full product name. | Use in formal contexts: documentation titles, system prompts, about screen. In casual messages, use "Claw." |
| **Dashboard** | The main screen showing status overview, stats, and recent activity. | Always capitalized as a page name. |
| **Ask Claw** | The conversational interface where users can ask Claw questions in natural language. | Always "Ask Claw," not "Chat" or "Assistant." |
| **My Tools** | The page listing all MCP servers and their status. | Always "My Tools," not "Servers" or "Server List." |
| **Activity** | The timeline page showing all MCP events in chronological order. | Always "Activity," not "Feed" or "Log" (those are internal terms). |
| **Alerts** | The page showing events that need attention or were flagged. | Always "Alerts," not "Warnings" or "Notifications." |

---

## Things Claw Talks About

| Term | Definition | When to Use | When NOT to Use |
|------|-----------|-------------|-----------------|
| **AI tools** | The applications the user interacts with: Cursor, Claude Desktop, Windsurf, etc. | Always in user-facing copy when referring to the user's applications. | Do not use "MCP clients" in user-facing copy. |
| **server** | The MCP server component that an AI tool uses to perform actions (read files, run commands, connect to APIs). | Use after context is established (e.g., after onboarding). In one-liners: "this server," "the server." | Do not say "MCP server" in user-facing copy. Reserve "MCP server" for developer documentation. |
| **agent** | A server or tool acting autonomously on behalf of the user. | Use only in the Guard context ("guard is protecting this agent") or when describing autonomous AI behavior. | Do not use as a general synonym for "server." |
| **tool call** | A single action a server performs: reading a file, running a command, making a network request. | Use in explanations: "A tool call is a single action a server takes." | Do not abbreviate to "call" without prior context. |
| **wrapping** | Routing a server's traffic through Claw so it can be monitored. | "Wrap this server" in action buttons. "I am not monitoring this server yet" in explanations. | Do not say "proxy" or "intercept" in user-facing copy. |

---

## Protection and Status

| Term | Definition | When to Use |
|------|-----------|-------------|
| **monitoring** | Claw is actively watching a server's traffic and analyzing its behavior. | For the active state: "I am monitoring 3 servers." |
| **protected** | A server is wrapped and Claw is monitoring it. | For the outcome/summary state: "3 servers protected." |
| **watching** | Informal synonym for monitoring. | In conversational contexts: "I am watching your AI tools." Avoid in status labels. |
| **protection score** | A 0-100 score showing how complete the user's security setup is. Higher is better. | Always lowercase unless starting a sentence. Never "Protection Score" as a brand name. |

---

## Risk Levels

These are the only labels shown to users. Internal scores and pattern IDs are never displayed.

| Label | Meaning | Color | When Used |
|-------|---------|-------|-----------|
| **Dangerous** | Requires immediate attention or was auto-blocked. Known attack pattern or very high confidence of malicious behavior. | Red | Kill chain detection, IoC match, anomaly score 0.9+ |
| **Suspicious** | High confidence something is wrong but not definitively malicious. User decision required. | Orange | Anomaly score 0.7-0.9 |
| **Unusual** | Behavioral deviation from what Claw has learned is normal. Logged and surfaced but does not block. | Amber | Anomaly score 0.4-0.7 |
| **Normal** | Within the server's learned behavioral baseline. | Green | Anomaly score below 0.4 |
| **Blocked** | Claw took automatic action to prevent the event. User can review. | Red | Auto-block by policy or decision engine |
| **Info** | System status message or advisory notice. | Amber | Mock mode, learning phase, educational context |

---

## Actions Claw Takes

| Term | Definition | When to Use |
|------|-----------|-------------|
| **blocked** | Claw prevented the action from completing. Final state. | When Claw auto-blocked or the user chose to block: "I blocked this." |
| **paused** | Claw intercepted the action and is waiting for the user to decide. | When Claw needs a user decision: "I paused this -- your call." |
| **allowed** | Claw let the action through, either automatically or by user decision. | "I allowed this." or "You allowed this." |
| **logged** | Claw recorded the event for later review. | "I logged this." Used alongside other actions: "I blocked it and logged the attempt." |

Note: Never use "stopped," "denied," "prevented," or "intercepted" in user-facing copy. Use "blocked" or "paused."

---

## Protection Modes

| Term | Definition |
|------|-----------|
| **Keep Watch** | Claw logs everything and alerts on suspicious activity but does not block anything. User stays in full control. |
| **Stay Sharp** | Claw blocks dangerous actions automatically and prompts the user for anything suspicious. The recommended default. |
| **Lock It Down** | Claw prompts the user for every action. Maximum control, more interruptions. |

---

## Features

| Term | Definition | User-Facing Name |
|------|-----------|-----------------|
| **behavioral analysis** | Claw learns what is normal for each server and flags deviations. | "behavioral analysis" (lowercase). Explain on first use: "I learn what is normal for each server and flag anything different." |
| **local model** | The on-device AI model that analyzes events for risk. | "local model" or "local AI." Never "SLM" in user-facing copy. |
| **cloud analysis** | Optional remote analysis for deeper risk assessment. | "cloud analysis" (lowercase). |
| **threat intelligence** | Database of known malicious indicators (IPs, hashes, patterns). | "threat intelligence" or "threat feed." Never "IoC database" or "blocklist" in user-facing copy. Explain on first use: "a database of known threats shared by the security community." |
| **guard** | An automated protection rule that watches for a specific pattern and acts on it. | "guard" (lowercase). Plural: "guards." |
| **scan** | A point-in-time security check of a server's configuration and known vulnerabilities. | "scan" (lowercase). |
| **audit log** | The complete record of every event Claw has seen, for forensic review. | "audit log" (lowercase). |

---

## System Terms (Explain Before Using)

These terms may appear in expanded views or educational asides. Always explain on first use.

| Term | Plain-Language Explanation |
|------|--------------------------|
| **process tree** | Every program a server has launched. "A process tree shows what programs this server is running." |
| **anomaly score** | Never shown as a number. Translated to risk labels (Dangerous, Suspicious, Unusual, Normal). |
| **kill chain** | A multi-step attack pattern. "A sequence of actions that together form an attack -- like scanning files, reading credentials, then trying to send them out." |
| **prompt injection** | Hidden instructions smuggled into AI inputs. "Prompt injection is when hidden instructions try to trick your AI into doing something it should not." |
| **exfiltration** | Sending sensitive data to an external server. "Exfiltration means your data is being sent somewhere it should not go." |
| **privilege escalation** | Gaining higher access than intended. "Privilege escalation is when a tool tries to gain more access than it should have." |
| **Full Disk Access (FDA)** | A macOS permission that lets Claw see all process activity. "Full Disk Access lets me see everything happening on your system, so I have no blind spots." |

---

## Terms Never Used in User-Facing Copy

| Internal Term | User-Facing Alternative |
|---------------|----------------------|
| MCP server | "server" (after context) or "AI tool" (general) |
| MCP client | "AI tool" (Cursor, Claude Desktop, etc.) |
| SLM | "local model" or "local AI" |
| IoC | "known threat" or "threat intelligence match" |
| CVE | "known security issue" or "vulnerability" (with ID in parentheses if needed) |
| anomaly score (as number) | Risk label: Dangerous, Suspicious, Unusual, Normal |
| policy rule | "rule" or "protection rule" |
| DecisionEngine | Never exposed. Claw says "I." |
| AnomalyScorer | Never exposed. Claw says "I." |
| KillChainDetector | Never exposed. Describe the pattern in plain language. |
| eslogger | "system sensor" |
