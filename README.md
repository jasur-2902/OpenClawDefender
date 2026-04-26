<p align="center">
  <img src="https://github.com/rookbot-io/rookbot/raw/main/assets/logo.png" alt="Rookbot" width="120" />
</p>

<h1 align="center">Rookbot</h1>

<p align="center">
  <strong>A firewall for AI agents.</strong><br/>
  Intercept, inspect, and control every MCP tool call — before it touches your system.
</p>

<p align="center">
  <a href="https://github.com/rookbot-io/rookbot/actions/workflows/ci.yml"><img src="https://github.com/rookbot-io/rookbot/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/rookbot-io/rookbot/releases"><img src="https://img.shields.io/github/v/release/rookbot-io/rookbot?label=release" alt="Release"></a>
  <a href="https://www.npmjs.com/package/rookbot"><img src="https://img.shields.io/npm/v/rookbot?color=cb3837" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"></a>
</p>

---

## What is Rookbot?

AI coding agents (Claude, Cursor, Windsurf, etc.) talk to tools through the [Model Context Protocol](https://modelcontextprotocol.io/). Those tools can read your files, run shell commands, and open network connections — with no security layer in between.

Rookbot is a transparent proxy that sits between the MCP client and server. Every tool call passes through Rookbot first, where it is evaluated against your policy rules, analyzed by an on-device AI model, and logged for audit.

```
MCP Client ──── Rookbot Proxy ──── MCP Server
 (Claude)        allow / block       (filesystem,
                  / prompt            git, shell)
```

If a tool call violates your policy, Rookbot blocks it. If it's ambiguous, Rookbot asks you. Everything is logged.

---

## Install

```bash
# npm (macOS + Linux)
npm install -g rookbot

# Homebrew (macOS + Linux)
brew install rookbot-io/tap/rookbot

# Shell script
curl -fsSL https://raw.githubusercontent.com/rookbot-io/rookbot/main/scripts/install.sh | bash

# Build from source
git clone https://github.com/rookbot-io/rookbot.git && cd rookbot
cargo build --workspace --release && just install
```

**Requirements:** macOS 13+ or Linux (x86_64 / arm64). Rust 1.70+ for building from source.

---

## Quick Start

```bash
# 1. Initialize config and data directories
rookbot init

# 2. Start the background daemon
rookbot daemon start

# 3. Download an on-device AI model for risk analysis (~1 GB)
rookbot model download qwen3-1.7b
rookbot model on

# 4. Protect all your MCP servers
rookbot wrap --all

# 5. Restart your MCP client (Claude Desktop, Cursor) — done.
```

Every tool call now flows through Rookbot. Check the dashboard:

```bash
rookbot status          # proxy & daemon status
rookbot log -n 20       # recent events
rookbot log --blocked   # blocked calls only
```

---

## How It Works

Rookbot operates in three layers:

### Layer 1 — MCP Proxy (blocking)

The proxy intercepts every JSON-RPC message between client and server. It evaluates each `tools/call`, `resources/read`, and `sampling/createMessage` against your TOML policy rules. Matching calls are allowed, blocked, or held for user prompt.

### Layer 2 — On-Device AI Analysis (advisory)

Tool calls that pass Layer 1 are analyzed by a local GGUF model (runs entirely on your machine — no data leaves your device). The model classifies risk as Low / Medium / High / Critical with an explanation. This enriches audit logs and alerts but never overrides policy decisions.

### Layer 3 — OS-Level Monitoring (observation)

On macOS, Rookbot observes actual system activity via `eslogger` — file access, process execution, network connections — and correlates it with MCP traffic. If an agent does something it didn't declare, Rookbot flags it.

---

## Key Features

**Policy Engine** — TOML rules for allow / deny / prompt per tool, per argument pattern, per server. Default-deny. First match wins.

**Behavioral Defense** — Learns per-server baselines, then detects anomalies across 9 dimensions. Recognizes 6 kill-chain attack patterns. Optional auto-block.

**Security Scanner** — 5 modules: config audit, policy strength, system posture (SIP, Gatekeeper, FileVault), behavioral anomaly, and fuzzing.

**Threat Intelligence** — Ed25519-signed threat feeds, IoC matching (IP, domain, hash, command pattern), server reputation checks.

**Prompt Injection Hardening** — Input sanitization, nonce delimiters, output validation, canary tokens. Fail-closed: unknown output defaults to HIGH risk.

**Cloud Escalation (BYOK)** — Optionally escalate ambiguous events to a multi-agent swarm (Anthropic / OpenAI). Keys stored in macOS Keychain. Daily/monthly budget caps.

**Desktop App** — Tauri GUI with real-time alerts, event timeline, AI analysis display, and interactive prompts.

---

## CLI Reference

```bash
rookbot init                          # Initialize config
rookbot daemon start|stop|status      # Manage background daemon
rookbot wrap <server> | --all         # Protect MCP servers
rookbot unwrap <server>               # Remove protection
rookbot status                        # Show proxy status

rookbot model list                    # Available AI models
rookbot model download <name>         # Download a model
rookbot model on|off                  # Enable/disable AI analysis

rookbot scan -- <server-command>      # Security scan an MCP server
rookbot log [-n 50] [--blocked]       # View audit log
rookbot policy list|reload|test       # Manage policy rules
rookbot doctor                        # Diagnostic checks

rookbot feed update                   # Update threat intelligence
rookbot reputation <server>           # Check server reputation
rookbot ioc add <indicator>           # Add custom IoC

rookbot config set-api-key            # Configure cloud API key (BYOK)
rookbot usage                         # Cloud API cost tracking
```

Run `rookbot --help` for the full command list (40+ subcommands).

---

## Writing Policy Rules

Policies live in `~/.config/rookbot/policy.toml`. Rules are evaluated top-to-bottom; first match wins.

```toml
# Block all shell execution
[[rule]]
action = "deny"
tool = "shell_execute"

# Ask before accessing system config
[[rule]]
action = "prompt"
tool = "filesystem_*"
args.path = "/etc/**"

# Allow reading project files
[[rule]]
action = "allow"
tool = "filesystem_read"
args.path = "/home/user/projects/**"

# Default deny
[[rule]]
action = "deny"
tool = "*"
```

Test policies before deploying:

```bash
rookbot policy test --policy policy.toml --fixture fixtures/read-ssh-key.json --expect deny
```

---

## Supported MCP Clients

| Client | Status |
|--------|--------|
| Claude Desktop | Supported — auto-detected by `rookbot wrap` |
| Cursor | Supported — auto-detected by `rookbot wrap` |
| VS Code (Copilot) | Planned |

---

## Configuration

| File | Purpose |
|------|---------|
| `~/.config/rookbot/config.toml` | Main configuration |
| `~/.config/rookbot/policy.toml` | Security policy rules |
| `~/.local/share/rookbot/audit.jsonl` | Audit log |
| `~/.local/share/rookbot/models/` | Downloaded AI models |

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](QUICKSTART.md) | 10-minute setup guide |
| [Architecture](docs/architecture.md) | System design and data flow |
| [MCP Protocol](docs/mcp-protocol.md) | How wrapping, interception, and policies work |
| [Behavioral Defense](docs/behavioral-guide.md) | Anomaly detection and kill-chain recognition |
| [SLM Guide](docs/slm-guide.md) | On-device AI model setup |
| [Sensor Guide](docs/sensor-guide.md) | macOS eslogger + FSEvents monitoring |
| [Swarm Guide](docs/swarm-guide.md) | Cloud escalation (BYOK) |
| [Threat Model](docs/threat-model.md) | What Rookbot protects against (and doesn't) |
| [Security Policy](SECURITY.md) | Vulnerability reporting |
| [Contributing](CONTRIBUTING.md) | How to build and contribute |

---

## License

MIT
