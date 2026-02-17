# ClawDefender Architecture

## Overview

ClawDefender is a security firewall for AI agents on macOS. It intercepts and
inspects operations performed by AI coding assistants (Claude Code, Cursor,
Windsurf, etc.) and enforces user-defined security policies in real time.

## High-Level Data Flow

```
                        AI Host (Claude Code, Cursor, etc.)
                                     |
                              JSON-RPC (stdio)
                                     |
                                     v
                        +------------------------+
                        |     MCP Proxy          |  <-- BLOCKING layer
                        |  (clawdefender-mcp-proxy)      |      Intercepts tool calls,
                        |                        |      resource reads, sampling
                        +----------+-------------+
                                   |
                    +--------------+--------------+
                    |                             |
                    v                             v
          +------------------+         +-------------------+
          |  Policy Engine   |         |  MCP Tool Server  |
          |  (clawdefender-core)     |         |  (downstream)     |
          +--------+---------+         +-------------------+
                   |
          allow / block / prompt
                   |
          +--------+---------+
          |  Audit Logger    |
          |  (JSON-lines)    |
          +------------------+

    Meanwhile, in parallel:

          +------------------+
          |  eslogger        |  <-- OBSERVATION layer
          |  (clawdefender-sensor)   |      Watches exec, open, connect,
          |                  |      rename, unlink, fork, exit, ...
          +--------+---------+
                   |
                   v
          +------------------+
          | Correlation      |      Links MCP tool calls to the
          | Engine           |      OS events they produce
          +--------+---------+
                   |
                   v
          +------------------+
          |  macOS Menu-Bar  |      Shows alerts, prompts user,
          |  UI (SwiftUI)    |      displays audit dashboard
          +------------------+
```

## Crate Responsibilities

### clawdefender-core

The shared type library. Contains no runtime logic beyond serialization and
configuration loading. Every other crate depends on this one.

| Module          | Purpose                                                   |
|-----------------|-----------------------------------------------------------|
| `event::mcp`   | MCP JSON-RPC event types (ToolCall, ResourceRead, etc.)   |
| `event::os`    | OS event types from eslogger (Exec, Open, Connect, etc.)  |
| `event::correlation` | Composite events linking MCP to OS activity          |
| `event` (mod)  | Common `Event` trait and `Severity` enum                  |
| `policy`       | PolicyRule, PolicyAction, Matcher/PolicyEngine traits      |
| `audit`        | AuditRecord, AuditLogger trait, AuditFilter, AuditStats   |
| `ipc`          | UiRequest/UiResponse protocol for daemon-UI communication |
| `config`       | ClawConfig loaded from TOML with sensible defaults        |

### clawdefender-mcp-proxy

A transparent JSON-RPC proxy that sits between the AI host and MCP tool
servers. It is the **blocking enforcement point**: every `tools/call`,
`resources/read`, and `sampling/createMessage` request passes through the
proxy, which consults the policy engine before forwarding.

Key design decisions:
- Stdio-based transport (wraps the real MCP server's stdin/stdout)
- Zero-copy parsing where possible; falls back to serde_json::Value
- Async (tokio) with a configurable timeout for policy decisions

### clawdefender-sensor

Wraps macOS `eslogger` (Endpoint Security framework) to observe OS-level
operations. Runs as a privileged helper (requires Full Disk Access or SIP
exception) and streams events to the daemon over a Unix domain socket.

| Module           | Purpose                                                    |
|------------------|------------------------------------------------------------|
| `eslogger`       | EsloggerManager: spawn, crash recovery, FDA detection      |
| `eslogger/filter`| EventPreFilter: noise reduction for high-volume events     |
| `eslogger/parser`| NDJSON parser with size limits and validation              |
| `eslogger/types` | Type definitions, path sanitization, OsEvent conversion   |
| `proctree`       | ProcessTree with ancestry cache, PID recycling protection  |
| `proctree/agent_id` | 4-layer agent identification (tagged, signature, heuristic, ancestry) |
| `fsevents`       | EnhancedFsWatcher: sensitivity tiers, debouncing, rate limiting |
| `correlation`    | CorrelationEngine: matches MCP events to OS events         |
| `correlation/rules` | 4 matching rules (exec, open, file op, network)         |
| `correlation/severity` | Uncorrelated event severity rating                   |
| `limits`         | ResourceLimits, ResourceMonitor for CPU/memory bounds      |

Observed event types:
- `exec` -- process execution
- `open` / `close` -- file access
- `rename` / `unlink` -- file modification/deletion
- `connect` -- network connections
- `fork` / `exit` -- process lifecycle
- `pty_grant` -- pseudoterminal grants
- `setmode` -- file permission changes

### clawdefender-daemon

The central orchestrator. Responsibilities:
1. Spawn and manage MCP proxies (multi-proxy architecture)
2. Start and monitor the sensor subsystem (process tree, eslogger, FSEvents)
3. Run the correlation engine (link MCP calls to OS events)
4. Route correlated events to audit, UI, and analysis subsystems
5. Send prompts/alerts to the UI over IPC
6. Write audit records
7. Hot-reload policy and sensor configuration

| Module          | Purpose                                                    |
|-----------------|------------------------------------------------------------|
| `lib`           | Daemon struct, sensor subsystem startup, proxy lifecycle   |
| `event_router`  | Routes CorrelatedEvents to audit, UI, and analysis sinks  |
| `ipc`           | Unix domain socket server for daemon-UI communication      |

### clawdefender-menubar (SwiftUI)

A macOS menu-bar application that:
- Shows real-time alerts for blocked/prompted events
- Displays a dashboard with audit statistics
- Lets the user respond to policy prompts (allow/deny/add rule)
- Provides a kill-process button for runaway agents

### clawdefender-slm

On-device small language model integration for AI-powered risk analysis.
The SLM evaluates tool calls that hit `prompt` policy rules and provides
advisory risk assessments without blocking.

| Module             | Purpose                                                    |
|--------------------|------------------------------------------------------------|
| `engine`           | Core inference engine with concurrency control and stats   |
| `analyzer`         | Prompt construction and output parsing pipeline            |
| `context`          | Per-server context tracking for pattern detection          |
| `noise_filter`     | Filters benign developer activity before SLM analysis      |
| `profiles`         | Built-in activity profiles (compilers, git, IDEs, etc.)    |
| `sanitizer`        | Input sanitization to prevent prompt injection             |
| `output_validator` | Validates SLM output for injection artifacts               |
| `model_manager`    | Download, verify, and manage GGUF model files              |

#### SLM Analysis Pipeline

```
Event (tool call / resource read)
          |
          v
    Noise Filter       -- Suppresses benign activity (compilers, git, etc.)
          |
          v (if not filtered)
    Input Sanitizer    -- Strips injection patterns, escapes special chars
          |
          v
    Random Delimiter   -- Wraps untrusted data with unique nonce tags
    Wrapper
          |
          v
    Prompt Builder     -- Constructs security-focused prompt with context
          |
          v
    SLM Engine         -- Runs local GGUF model inference (1 at a time)
          |
          v
    Output Validator   -- Checks for echo attacks, injection artifacts
          |
          v
    Canary Verifier    -- Confirms response was not hijacked
          |
          v
    Risk Assessment    -- LOW / MEDIUM / HIGH / CRITICAL + explanation
    (advisory only)
```

The SLM result is attached to the audit record and displayed in the TUI
but does not override policy decisions.

### clawdefender-swarm

Cloud-powered multi-agent swarm analysis using a Bring Your Own Key (BYOK) model.
When the local SLM flags an event as ambiguous or high-risk, the swarm provides
deeper analysis by dispatching to three specialist agents in parallel.

| Module             | Purpose                                                    |
|--------------------|------------------------------------------------------------|
| `keychain`         | Secure API key storage (macOS Keychain + in-memory fallback) |
| `llm_client`       | Unified LLM client supporting Anthropic and OpenAI APIs    |
| `prompts`          | Prompt construction with nonce-based injection hardening    |
| `commander`        | Swarm orchestrator: parallel dispatch and verdict synthesis |
| `cost`             | Token tracking, budget enforcement, usage database         |
| `chat`             | Conversation manager for follow-up questions on events     |
| `chat_server`      | Axum-based web server for the chat UI                      |
| `data_minimizer`   | Strips PII/secrets from data before sending to cloud       |
| `output_sanitizer` | Validates specialist responses for injection artifacts     |
| `audit_hasher`     | SHA-256 chain hashing for tamper-evident audit records      |

#### Swarm Analysis Pipeline

```
SLM flags event >= escalation threshold
          |
          v
    Data Minimizer      -- Strips secrets/PII before cloud upload
          |
          v
    Commander            -- Dispatches to 3 specialists in parallel
          |
    +-----+-----+
    |     |     |
    v     v     v
  Hawk  Forensics  Internal Affairs
    |     |     |
    +-----+-----+
          |
          v
    Output Sanitizer    -- Checks specialist responses for injection
          |
          v
    Synthesis Engine    -- Merges 3 reports into final verdict
          |
          v
    Cost Tracker        -- Records tokens, checks budget limits
          |
          v
    SwarmVerdict        -- risk_level, explanation, action, confidence
```

The Commander uses rule-based synthesis:
- If ANY specialist says CRITICAL, final verdict is CRITICAL
- If 2+ say HIGH, final verdict is HIGH
- If 1 says HIGH (dissent), downgraded to MEDIUM
- Otherwise, median risk level

## Full System Data Flow (Three Event Sources)

```
MCP Client (Claude Code, Cursor, etc.)
       |
  JSON-RPC (stdio or HTTP)
       |
       v
+--------------------+         +--------------------+
|   MCP Proxy        |  <--    |  ClawDefender      |  <-- SDK REPORTING
|  (per-server)      |   |     |  MCP Server        |      Agents call
|  BLOCKING layer    |   |     |  (clawdefender-    |      checkIntent,
+--------+-----------+   |     |   mcp-server)      |      reportAction, etc.
         |               |     +--------+-----------+
         |               |              |
  Source 1: Proxy        |       Source 2: SDK
  Interception           |       Self-Reporting
         |               |              |
         v               v              v
       +------------------------------------+
       |        Correlation Engine          |  <--- Source 3: OS Sensor
       |  Merges proxy, SDK, and OS events  |       eslogger + FSEvents
       +--------+---------------------------+
                |
                v
          Event Router
         /     |      \
        v      v       v
  Audit Log  TUI /    SLM / Swarm
             Menu Bar  (analysis)
```

### Three Event Sources

1. **Proxy Interception** (Source 1): The MCP proxy sits between client and server,
   intercepting every JSON-RPC message. This is the blocking enforcement point.

2. **SDK Self-Reporting** (Source 2): MCP servers that integrate the ClawDefender
   SDK (Python or TypeScript) voluntarily declare intent, request permission,
   and report actions via the ClawDefender MCP server.

3. **OS Sensor** (Source 3): macOS eslogger and FSEvents observe actual system-level
   activity (file access, process execution, network connections) independently.

The correlation engine merges all three sources to detect discrepancies between
declared behavior (SDK reports), observed MCP traffic (proxy), and actual system
activity (OS sensor).

### ClawDefender MCP Server

The MCP server (`clawdefender-mcp-server`) exposes four tools via the MCP protocol:

| Tool | Purpose |
|------|---------|
| `checkIntent` | Pre-flight check: will this action be allowed by policy? |
| `requestPermission` | Request explicit approval for a resource operation |
| `reportAction` | Post-action audit: log what was actually performed |
| `getPolicy` | Query current policy rules for planning |

SDK clients (Python, TypeScript) connect to this server over stdio or HTTP
and use these tools to participate cooperatively in the security model.

### Sensor Subsystem Detail

```
+------------------+     +------------------+
|   eslogger       |     |   FSEvents       |
|  (exec, open,    |     |  (file changes   |
|   connect, fork, |     |   with debounce  |
|   exit, ...)     |     |   + rate limit)  |
+--------+---------+     +--------+---------+
         |                         |
         |  OsEvent                | FsEvent -> OsEvent
         v                         v
     EventPreFilter          Sensitivity
     (ignore noise)          Classifier
         |                         |
         +----------+--------------+
                    |
                    v
          Correlation Engine
          (4 matching rules:
           ToolCall->Exec,
           ResourceRead->Open,
           FileTool->FileOp,
           NetworkTool->Connect)
                    |
          +---------+---------+
          |                   |
    Matched              Uncorrelated
    (MCP + OS)           (OS only, rated
                          by severity)
```

## Two-Layer Security Model

### Layer 1: MCP Proxy (Blocking)

The proxy is the **active enforcement** layer. It can block, allow, or prompt
for every MCP operation before it reaches the tool server. This is the primary
security boundary.

### Layer 2: eslogger (Observation)

The sensor is the **passive observation** layer. It cannot block operations
(Endpoint Security AUTH events require a kernel extension or system extension,
which is out of scope for v1), but it provides ground-truth visibility into
what the agent process tree actually does on disk and network.

### Correlation

The correlation engine links Layer 1 and Layer 2 by matching MCP tool calls
to the OS events they produce. For example, when the proxy sees a
`tools/call: write_file`, the correlator watches for the subsequent `open` +
`close` events from the same process tree and bundles them into a
`CorrelatedEvent`.

## Policy System

Policies are TOML files containing an ordered list of rules. Each rule has:
- **match_criteria**: tool names, resource paths, methods, event types (supports globs)
- **action**: Allow, Block, Prompt, or Log
- **priority**: lower numbers evaluate first; first match wins

Rules can be:
- **Permanent**: persisted in `~/.config/clawdefender/policy.toml`
- **Session**: created via the UI prompt flow, active until daemon restart

## IPC Protocol

The daemon and UI communicate over a Unix domain socket at
`~/.local/share/clawdefender/clawdefender.sock` using length-prefixed JSON frames.

Message types:
- `UiRequest::PromptUser` -- daemon asks user for a decision
- `UiRequest::Alert` -- daemon pushes an alert
- `UiRequest::StatusUpdate` -- periodic dashboard update
- `UiResponse::Decision` -- user's allow/deny choice
- `UiResponse::KillProcess` -- user requests process termination
- `UiResponse::Dismiss` -- user dismisses an alert

## Audit Trail

Every event that passes through the policy engine is logged to a JSON-lines
file at `~/.local/share/clawdefender/audit.jsonl`. Each line is a serialized
`AuditRecord` containing the timestamp, source, event summary, full event
details, matched rule, action taken, and response time.

Log rotation is configurable (default: 50 MB max, 10 rotated files).
