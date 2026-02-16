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

## Quick Start

```bash
# Install
curl -fsSL https://clawai.dev/install.sh | sh

# Initialize a default policy
clawai init

# Wrap an MCP server with ClawAI protection
clawai wrap filesystem-server
```

`clawai init` generates a default policy file at `~/.config/clawai/policy.toml`. Edit it to define what tools are allowed, denied, or require interactive approval.

`clawai wrap` rewrites your MCP client configuration so that ClawAI sits between the client and server transparently.

## Features

- **MCP interception** — stdio man-in-the-middle for local servers, HTTP reverse proxy for remote servers.
- **Policy engine** — TOML-based rules: allow, deny, or prompt per tool, per argument pattern, per server.
- **Interactive prompts** — when a tool call matches a `prompt` rule, ClawAI asks you before forwarding it.
- **Audit logging** — structured logs of every intercepted call, decision made, and response returned.
- **OS-level monitoring** — macOS `eslogger` integration observes file access, process execution, and network activity at the kernel event level.
- **Process tree agent identification** — traces which agent spawned which process to correlate MCP calls with actual system activity.
- **Event correlation** — links MCP tool calls to the OS-level events they produce, detecting discrepancies between declared and actual behavior.

## Non-features (honest limitations)

- **eslogger is NOTIFY-only.** ClawAI blocks at the MCP proxy layer. At the OS layer, `eslogger` can only *observe*, not prevent. If an agent bypasses MCP entirely (e.g., a shell command spawns a subprocess that phones home), ClawAI will detect it in the audit log but cannot block it retroactively.
- **Actions outside MCP are detected, not prevented.** ClawAI's enforcement boundary is the MCP protocol. Anything that happens outside that boundary is visible via OS monitoring but not controllable.
- **macOS only for OS monitoring.** The `eslogger` integration is macOS-specific. The MCP proxy and policy engine work cross-platform; OS-level monitoring does not (yet).

## Architecture

ClawAI is structured as a Cargo workspace with the following crates:

| Crate | Purpose |
|---|---|
| `clawai-cli` | Command-line interface (`clawai init`, `clawai wrap`, etc.) |
| `clawai-proxy` | MCP proxy — stdio and HTTP modes |
| `clawai-policy` | Policy engine — parses TOML rules, evaluates tool calls |
| `clawai-audit` | Structured audit logging |
| `clawai-monitor` | OS-level monitoring via `eslogger` |
| `clawai-correlate` | Links MCP events with OS events |
| `clawai-common` | Shared types, MCP protocol definitions, error types |

## Documentation

- [Architecture & Threat Model](docs/threat-model.md)
- [MCP Protocol Reference](docs/mcp-protocol.md)
- [Architecture Decision Records](docs/adr/)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## License

MIT
