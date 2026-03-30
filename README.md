# ClawDefender

**A firewall for AI agents.** Intercepts, inspects, and controls what AI tools can do on your machine -- with on-device AI risk analysis.

[![CI](https://github.com/clawdefender/clawdefender/actions/workflows/ci.yml/badge.svg)](https://github.com/clawdefender/clawdefender/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/clawdefender/clawdefender)](https://github.com/clawdefender/clawdefender/releases)

---

## Why ClawDefender?

AI agents communicating via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) can read your files, execute shell commands, and make network requests. There is no standardized security layer between what an agent *wants* to do and what it *actually does*.

ClawDefender fills that gap. It sits between the MCP client and server, enforcing policies you define before any tool call reaches your system -- and uses an on-device AI model to classify risk in real time.

## Quick Start

See **[QUICKSTART.md](QUICKSTART.md)** for a step-by-step setup guide covering build, install, daemon startup, model download, and first scan.

```bash
git clone https://github.com/clawdefender/clawdefender.git
cd clawdefender
cargo build --workspace --release
just install
clawdefender init
clawdefender daemon start
clawdefender model download qwen3-1.7b
clawdefender model on
clawdefender wrap --all
```

## How It Works

```
MCP Client           ClawDefender              MCP Server
(Claude,    ──────>  Proxy ──> Policy   ──────>  (filesystem,
 Cursor)             Engine    Engine             git, etc.)
            <──────           <──────
                        |
                   EventRouter
                  /     |     \
          Behavioral  Kill    SLM Analysis
          Scoring     Chain   (on-device AI)
                  \     |     /
                   Alert Engine
                   Audit Logger
                        |
                   GUI / CLI / Notifications
```

The proxy intercepts every JSON-RPC message. The policy engine evaluates each tool call against your rules. Allowed calls pass through; denied calls are blocked. The SLM (small language model) classifies risk in real time. The OS monitor independently observes what actually happens at the system level for correlation and audit.

## Features

### Core Security
- **MCP interception** -- stdio man-in-the-middle for local servers, HTTP reverse proxy for remote servers
- **Policy engine** -- TOML-based rules: allow, deny, or prompt per tool, per argument pattern, per server
- **Interactive prompts** -- when a tool call matches a `prompt` rule, ClawDefender asks you before forwarding it
- **Audit logging** -- structured JSONL logs of every intercepted call, decision made, and response returned
- **Path canonicalization** -- prevents path traversal attacks in policy matching

### AI-Powered Analysis
- **On-device SLM risk analysis** -- 5 GGUF models (229 MB to 2.2 GB) run locally on your machine. No data leaves your device
- **Risk classification** -- each tool call is classified as Low/Medium/High/Critical with an explanation
- **Cloud fallback chain** -- GGUF -> Cloud (Anthropic/OpenAI) -> Mock, with data minimization for cloud requests
- **Fail-closed parsing** -- unknown or malformed AI output defaults to HIGH risk
- **Prompt injection hardening** -- input sanitization, nonce delimiters, output validation, canary tokens

### Behavioral Defense
- **Behavioral baselines** -- learns per-server behavioral patterns, then detects anomalies across 9 dimensions (unknown tools, paths, network, rate, sequence, arguments, sensitive targets, first network access, privilege escalation)
- **Kill chain recognition** -- detects 6 multi-step attack patterns (credential theft, reconnaissance, persistence, data staging, shell escape, prompt injection followthrough)
- **Real-time alerts** -- 9 alert rules including SLM-driven Rule 9 for AI-flagged high-risk events
- **Anomaly-based escalation** -- events with anomaly score >= 0.6 are escalated to SLM analysis with rate limiting (5/min)

### OS-Level Monitoring
- **eslogger integration** -- observes file access, process execution, and network activity at the kernel event level
- **Process tree identification** -- traces which AI agent spawned which process
- **Event correlation** -- links MCP tool calls to OS-level events, detecting discrepancies between declared and actual behavior
- **FSEvents monitoring** -- file system event watching with sensitivity classification and debouncing

### Security Scanning
- **5 scanner modules** -- config audit, policy strength, system posture, behavioral anomaly, fuzzing
- **System posture checks** -- SIP, Gatekeeper, Firewall, FileVault, auto-updates, SSH, Full Disk Access
- **Threat intelligence** -- Ed25519-signed threat feeds, IoC engine (IP, CIDR, domain, hash, command pattern), community rule packs
- **Server reputation** -- check any server against the blocklist and IoC database

### Cloud Escalation (Optional, BYOK)
- **Multi-agent swarm** -- escalates ambiguous events to three specialist agents (Hawk, Forensics, Internal Affairs) for deep analysis
- **Budget controls** -- daily and monthly spending caps with cost tracking
- **API key management** -- stored in macOS Keychain, never written to disk or logs

### Interfaces
- **CLI** -- 20+ subcommands for daemon management, model management, policy, scanning, threat intel, and more
- **Tauri GUI** -- desktop application with alerts, events, prompts, AI analysis display, and settings
- **Cooperative SDK** -- Python and TypeScript SDKs for MCP servers to voluntarily declare intent and request permission

## Supported MCP Clients

| Client | Status | Notes |
|---|---|---|
| Claude Desktop | Supported | Auto-detected by `clawdefender wrap`. Supports mcpServers config and DXT extensions. |
| Cursor | Supported | Auto-detected by `clawdefender wrap` |
| VS Code (Copilot) | Planned | Coming in a future release |

## System Requirements

- **macOS Ventura (13.0)** or later
- **Rust toolchain** (1.70+) -- for building from source
- **Full Disk Access** -- required for eslogger (grant in System Settings > Privacy & Security)
- **Node.js 18+** -- required only for building the GUI app

The MCP proxy and policy engine work on any platform; OS-level monitoring and the GUI app are macOS-specific.

## Architecture

ClawDefender is structured as a Cargo workspace:

| Crate | Purpose |
|---|---|
| `clawdefender-cli` | Command-line interface |
| `clawdefender-daemon` | Background daemon orchestrating all components |
| `clawdefender-core` | Policy engine, audit, behavioral analysis, event correlation |
| `clawdefender-mcp-proxy` | MCP proxy -- stdio and HTTP modes |
| `clawdefender-mcp-server` | Cooperative SDK endpoint (checkIntent, reportAction, getPolicy) |
| `clawdefender-sensor` | OS-level monitoring via eslogger + FSEvents |
| `clawdefender-slm` | On-device AI model management and inference |
| `clawdefender-swarm` | Cloud multi-agent analysis (BYOK) |
| `clawdefender-scanner` | 5-module security scanner |
| `clawdefender-threat-intel` | Threat feeds, IoC engine, community rule packs |
| `clawdefender-guard` | Agent guard system with API auth |
| `clawdefender-certify` | MCP server compliance testing (Level 1-3) |
| `clawdefender-tui` | Terminal UI (ratatui) |
| `clawdefender-app` | Tauri GUI desktop application |

## Known Limitations

- **eslogger is NOTIFY-only.** OS-level monitoring can observe but not block. Enforcement happens at the MCP proxy layer.
- **Network extension requires Apple signing.** Network-level blocking is designed but not deployable without a System Extension entitlement.
- **SLM analysis is advisory.** AI risk assessments inform alerts and escalation but do not block on their own. Policy rules remain the enforcement mechanism.
- **macOS only for OS monitoring.** The MCP proxy and policy engine work cross-platform; eslogger, FSEvents, and the desktop app are macOS-specific.

## Documentation

- [Quick Start Guide](QUICKSTART.md)
- [Phase 6 Final Status](PHASE6-FINAL-STATUS.md)
- [Architecture](docs/architecture.md)
- [Sensor Guide](docs/sensor-guide.md)
- [SLM Guide](docs/slm-guide.md)
- [Behavioral Defense Guide](docs/behavioral-guide.md)
- [Swarm Guide](docs/swarm-guide.md)
- [Threat Model](docs/threat-model.md)
- [MCP Protocol Reference](docs/mcp-protocol.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## License

MIT
