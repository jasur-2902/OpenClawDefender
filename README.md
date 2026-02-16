# ClawAI

**A firewall for AI agents.** Intercepts, inspects, and controls what AI tools can do on your machine.

[![CI](https://github.com/clawai/clawai/actions/workflows/ci.yml/badge.svg)](https://github.com/clawai/clawai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/clawai/clawai)](https://github.com/clawai/clawai/releases)

---

## Why ClawAI?

AI agents communicating via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) can read your files, execute shell commands, and make network requests. There is no standardized security layer between what an agent *wants* to do and what it *actually does*.

ClawAI fills that gap. It sits between the MCP client and server, enforcing policies you define before any tool call reaches your system.

## How it works

```
┌────────────┐      ┌───────────────┐      ┌────────────┐
│  MCP Client│─────▶│  ClawAI Proxy │─────▶│ MCP Server │
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
curl -sSL https://clawai.dev/install.sh | sh
```

**Homebrew:**

```bash
brew install clawai
```

**From source:**

```bash
git clone https://github.com/clawai/clawai.git
cd clawai
cargo build --release
```

## Quick Start

### 1. Initialize ClawAI

```bash
clawai init
```

This generates a default policy file at `~/.config/clawai/policy.toml` with sensible defaults: block access to SSH keys, prompt on shell execution, and allow everything else.

### 2. Wrap an MCP server

```bash
clawai wrap filesystem-server
```

This rewrites your MCP client configuration so that ClawAI sits between the client and server transparently. If you use Claude Desktop, the config at `~/Library/Application Support/Claude/claude_desktop_config.json` is updated automatically.

### 3. Restart your MCP client

Restart Claude Desktop (or your MCP client). ClawAI is now intercepting all tool calls.

### 4. Verify it's working

Open the ClawAI TUI to see intercepted events in real time:

```bash
clawai tui
```

Or trigger a blocked action and check the audit log:

```bash
clawai log --blocked
```

You should see blocked events for any tool calls that violate your policy.

### 5. Customize your policy

Edit `~/.config/clawai/policy.toml` to define your own rules:

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

## Supported MCP Clients

| Client | Status | Notes |
|---|---|---|
| Claude Desktop | Supported | Auto-detected by `clawai wrap` |
| Cursor | Supported | Auto-detected by `clawai wrap` |
| VS Code (Copilot) | Planned | Coming in a future release |

## Features

- **MCP interception** -- stdio man-in-the-middle for local servers, HTTP reverse proxy for remote servers.
- **Policy engine** -- TOML-based rules: allow, deny, or prompt per tool, per argument pattern, per server.
- **Interactive prompts** -- when a tool call matches a `prompt` rule, ClawAI asks you before forwarding it via a terminal TUI.
- **Audit logging** -- structured JSONL logs of every intercepted call, decision made, and response returned. Query with `clawai log`.
- **Terminal TUI** -- real-time dashboard showing intercepted events, policy decisions, and interactive prompt handling.
- **CLI tooling** -- `clawai init`, `clawai wrap`/`unwrap`, `clawai log`, `clawai policy test` for managing your setup.
- **Path canonicalization** -- prevents path traversal attacks (e.g., `../../etc/passwd`) in policy matching.
- **Prompt rate limiting** -- auto-blocks MCP servers that flood the user with prompt-triggering calls.
- **Parser hardening** -- enforces message size limits, JSON depth limits, and buffer overflow protection.
- **OS-level monitoring** -- macOS `eslogger` integration observes file access, process execution, and network activity at the kernel event level.
- **Process tree agent identification** -- traces which agent spawned which process to correlate MCP calls with actual system activity.
- **Event correlation** -- links MCP tool calls to the OS-level events they produce, detecting discrepancies between declared and actual behavior.

## Non-features (honest limitations)

- **eslogger is NOTIFY-only.** ClawAI blocks at the MCP proxy layer. At the OS layer, `eslogger` can only *observe*, not prevent. If an agent bypasses MCP entirely (e.g., a shell command spawns a subprocess that phones home), ClawAI will detect it in the audit log but cannot block it retroactively.
- **Actions outside MCP are detected, not prevented.** ClawAI's enforcement boundary is the MCP protocol. Anything that happens outside that boundary is visible via OS monitoring but not controllable.
- **macOS only for OS monitoring.** The `eslogger` integration is macOS-specific. The MCP proxy and policy engine work cross-platform; OS-level monitoring does not (yet).
- **No SLM-based analysis yet.** On-device small language model analysis of tool call intent is planned for Phase 2.

## Architecture

ClawAI is structured as a Cargo workspace with the following crates:

| Crate | Purpose |
|---|---|
| `claw-cli` | Command-line interface (`clawai init`, `clawai wrap`, etc.) |
| `claw-mcp-proxy` | MCP proxy -- stdio and HTTP modes |
| `claw-core` | Core types, policy engine, audit, event correlation |
| `claw-sensor` | OS-level monitoring via `eslogger` |
| `claw-tui` | Terminal UI for real-time monitoring and prompts |
| `claw-daemon` | Background daemon orchestrating all components |
| `claw-slm` | Small language model integration (Phase 2) |
| `claw-swarm` | Multi-agent coordination (Phase 2) |

## Documentation

- [Architecture & Threat Model](docs/threat-model.md)
- [MCP Protocol Reference](docs/mcp-protocol.md)
- [V1 Release Notes](docs/v1-release-notes.md)
- [Architecture Decision Records](docs/adr/)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## License

MIT
