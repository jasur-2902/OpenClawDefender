# ClawDefender

**A firewall for AI agents.** Intercepts, inspects, and controls what AI tools can do on your machine.

[![CI](https://github.com/clawdefender/clawdefender/actions/workflows/ci.yml/badge.svg)](https://github.com/clawdefender/clawdefender/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/clawdefender/clawdefender)](https://github.com/clawdefender/clawdefender/releases)

---

## Why ClawDefender?

AI agents communicating via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) can read your files, execute shell commands, and make network requests. There is no standardized security layer between what an agent *wants* to do and what it *actually does*.

ClawDefender fills that gap. It sits between the MCP client and server, enforcing policies you define before any tool call reaches your system.

## How it works

```
┌────────────┐      ┌───────────────┐      ┌────────────┐
│  MCP Client│─────▶│  ClawDefender Proxy │─────▶│ MCP Server │
│  (Claude,  │      │               │      │ (filesystem│
│   Cursor)  │◀─────│ Policy Engine │◀─────│  git, etc) │
└────────────┘      └──────┬────────┘      └────────────┘
                           │
                    ┌──────▼────────┐
                    │  Audit Log    │
                    │  OS Monitor   │
                    │  (eslogger)   │
                    └───────────────┘
```

The proxy intercepts every JSON-RPC message. The policy engine evaluates each tool call against your rules. Allowed calls pass through; denied calls are blocked before they reach the server. The OS monitor (via macOS `eslogger`) independently observes what actually happens at the system level for correlation and audit.

## Installation

**Install script (recommended):**

```bash
curl -sSL https://clawdefender.dev/install.sh | sh
```

**Homebrew:**

```bash
brew install clawdefender
```

**From source:**

```bash
git clone https://github.com/clawdefender/clawdefender.git
cd clawdefender
cargo build --release
```

## Quick Start

### 1. Initialize ClawDefender

```bash
clawdefender init
```

This generates a default policy file at `~/.config/clawdefender/policy.toml` with sensible defaults: block access to SSH keys, prompt on shell execution, and allow everything else.

### 2. Wrap an MCP server

```bash
clawdefender wrap filesystem-server
```

This rewrites your MCP client configuration so that ClawDefender sits between the client and server transparently. If you use Claude Desktop, the config at `~/Library/Application Support/Claude/claude_desktop_config.json` is updated automatically.

### 3. Restart your MCP client

Restart Claude Desktop (or your MCP client). ClawDefender is now intercepting all tool calls.

### 4. Verify it's working

Open the ClawDefender TUI to see intercepted events in real time:

```bash
clawdefender tui
```

Or trigger a blocked action and check the audit log:

```bash
clawdefender log --blocked
```

You should see blocked events for any tool calls that violate your policy.

### 5. Customize your policy

Edit `~/.config/clawdefender/policy.toml` to define your own rules:

```toml
[rules.block_ssh]
description = "Block SSH key access"
action = "block"
message = "SSH key access is not allowed"
priority = 0

[rules.block_ssh.match]
resource_path = ["~/.ssh/id_*"]

[rules.prompt_exec]
description = "Prompt on shell execution"
action = "prompt"
message = "Allow shell execution?"
priority = 1

[rules.prompt_exec.match]
event_type = ["exec"]
```

### 6. Enable AI-powered risk analysis (optional)

Download a small language model for on-device risk analysis:

```bash
clawdefender model download
```

Check installed models:

```bash
clawdefender model list
```

Toggle SLM analysis on or off:

```bash
clawdefender model toggle on
clawdefender model toggle off
```

View model statistics:

```bash
clawdefender model stats
```

When enabled, the SLM analyzes tool calls that match `prompt` rules and provides risk assessments (Low/Medium/High/Critical) with explanations in the TUI and audit log.

### 7. Cloud-Powered Deep Analysis (optional)

For events that the local SLM flags as ambiguous or high-risk, ClawDefender can escalate to a cloud-based multi-agent swarm for deeper analysis. This requires your own API key (Bring Your Own Key).

**Set up your API key:**

```bash
# Store your Anthropic API key in the macOS Keychain
clawdefender chat setup
```

ClawDefender stores API keys in the macOS Keychain (or an in-memory store on other platforms). Keys are never written to disk or included in logs.

**Configure escalation and budget:**

Edit `~/.config/clawdefender/clawdefender.toml`:

```toml
[swarm]
enabled = true
escalation_threshold = "MEDIUM"   # Escalate when SLM risk >= this level
daily_budget_usd = 1.00           # Hard spending cap per day
monthly_budget_usd = 20.00        # Hard spending cap per month
```

**How escalation works:**

When the local SLM flags an event at or above the escalation threshold, ClawDefender dispatches it to three specialist agents in parallel:

1. **Hawk** -- Network & exfiltration analyst
2. **Forensics** -- Command & code forensics analyst
3. **Internal Affairs** -- Prompt injection & intent analyst

The Commander synthesizes their findings into a final verdict with risk level, explanation, recommended action, and confidence score. All specialist outputs are sanitized for prompt injection before synthesis.

**Chat UI for investigating flagged events:**

```bash
# Start the chat web UI on localhost:3000
clawdefender chat serve

# List recent chat sessions
clawdefender chat sessions
```

The chat UI lets you ask follow-up questions about flagged events, with full conversation history stored locally.

**Monitor usage and costs:**

```bash
clawdefender chat usage
```

## Supported MCP Clients

| Client | Status | Notes |
|---|---|---|
| Claude Desktop | Supported | Auto-detected by `clawdefender wrap` |
| Cursor | Supported | Auto-detected by `clawdefender wrap` |
| VS Code (Copilot) | Planned | Coming in a future release |

## Features

- **MCP interception** -- stdio man-in-the-middle for local servers, HTTP reverse proxy for remote servers.
- **Policy engine** -- TOML-based rules: allow, deny, or prompt per tool, per argument pattern, per server.
- **Interactive prompts** -- when a tool call matches a `prompt` rule, ClawDefender asks you before forwarding it via a terminal TUI.
- **Audit logging** -- structured JSONL logs of every intercepted call, decision made, and response returned. Query with `clawdefender log`.
- **Terminal TUI** -- real-time dashboard showing intercepted events, policy decisions, and interactive prompt handling.
- **CLI tooling** -- `clawdefender init`, `clawdefender wrap`/`unwrap`, `clawdefender log`, `clawdefender policy test` for managing your setup.
- **Path canonicalization** -- prevents path traversal attacks (e.g., `../../etc/passwd`) in policy matching.
- **AI-powered risk analysis** -- on-device small language model (SLM) evaluates tool call intent and assigns risk levels (Low/Medium/High/Critical) with explanations. Runs locally, no data leaves your machine.
- **Noise filter** -- automatically suppresses benign developer activity (compilers, git, IDEs, package managers, test runners) from SLM analysis to reduce overhead.
- **Prompt injection hardening** -- multi-layer defense against prompt injection in SLM analysis: input sanitization, random nonce delimiters, output validation, canary tokens, and echo detection.
- **Cloud-powered deep analysis** -- escalates ambiguous events to a multi-agent swarm (Hawk, Forensics, Internal Affairs) for deeper analysis using your own API key. Budget controls prevent runaway costs.
- **Chat UI** -- web-based chat interface for investigating flagged events with follow-up questions and full conversation history.
- **BYOK API key management** -- securely stores API keys in the macOS Keychain with auto-detection of provider from key prefix.
- **Prompt rate limiting** -- auto-blocks MCP servers that flood the user with prompt-triggering calls.
- **Parser hardening** -- enforces message size limits, JSON depth limits, and buffer overflow protection.
- **OS-level monitoring** -- macOS `eslogger` integration observes file access, process execution, and network activity at the kernel event level.
- **Process tree agent identification** -- traces which agent spawned which process to correlate MCP calls with actual system activity.
- **Event correlation** -- links MCP tool calls to the OS-level events they produce, detecting discrepancies between declared and actual behavior.

## Non-features (honest limitations)

- **eslogger is NOTIFY-only.** ClawDefender blocks at the MCP proxy layer. At the OS layer, `eslogger` can only *observe*, not prevent. If an agent bypasses MCP entirely (e.g., a shell command spawns a subprocess that phones home), ClawDefender will detect it in the audit log but cannot block it retroactively.
- **Actions outside MCP are detected, not prevented.** ClawDefender's enforcement boundary is the MCP protocol. Anything that happens outside that boundary is visible via OS monitoring but not controllable.
- **macOS only for OS monitoring.** The `eslogger` integration is macOS-specific. The MCP proxy and policy engine work cross-platform; OS-level monitoring does not (yet).
- **SLM analysis is advisory only.** The on-device SLM provides risk assessments as additional context in the audit log and TUI, but does not block actions on its own. Policy rules remain the enforcement mechanism.

## Architecture

ClawDefender is structured as a Cargo workspace with the following crates:

| Crate | Purpose |
|---|---|
| `clawdefender-cli` | Command-line interface (`clawdefender init`, `clawdefender wrap`, etc.) |
| `clawdefender-mcp-proxy` | MCP proxy -- stdio and HTTP modes |
| `clawdefender-core` | Core types, policy engine, audit, event correlation |
| `clawdefender-sensor` | OS-level monitoring via `eslogger` |
| `clawdefender-tui` | Terminal UI for real-time monitoring and prompts |
| `clawdefender-daemon` | Background daemon orchestrating all components |
| `clawdefender-slm` | Small language model integration for risk analysis |
| `clawdefender-swarm` | Cloud-powered multi-agent swarm analysis (BYOK) |

## Documentation

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [SLM Guide](docs/slm-guide.md)
- [MCP Protocol Reference](docs/mcp-protocol.md)
- [Swarm Guide](docs/swarm-guide.md)
- [V3 Release Notes](docs/v3-release-notes.md)
- [V2 Release Notes](docs/v2-release-notes.md)
- [V1 Release Notes](docs/v1-release-notes.md)
- [Architecture Decision Records](docs/adr/)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## License

MIT
