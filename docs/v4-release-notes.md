# v0.4.0 Release Notes

## What's new

### OS-Level Sensor

ClawDefender v0.4.0 introduces a full OS-level sensor subsystem that monitors system activity from AI agent processes in real time. The sensor uses macOS Endpoint Security (`eslogger`) and FSEvents to observe process execution, file access, network connections, and more.

Key capabilities:
- **eslogger integration** with pre-filtering, crash recovery, and automatic FDA detection
- **Event types**: `exec`, `open`, `close`, `rename`, `unlink`, `connect`, `fork`, `exit`, `pty_grant`, `setmode`
- **Configurable ignore lists** for processes and paths to reduce noise
- **Graceful degradation** -- the MCP proxy continues working if eslogger is unavailable

### Correlation Engine

The correlation engine links MCP tool calls to the OS-level events they produce, providing ground-truth verification of agent behavior.

Four matching rules:
1. **ToolCall to Exec** -- shell tool calls matched to process execution
2. **ResourceRead to Open** -- resource reads with `file://` URIs matched to file opens
3. **FileTool to FileOp** -- file tool calls matched to file operations
4. **NetworkTool to Connect** -- network tool calls matched to outbound connections

Features:
- Configurable time window for matching (default: 500ms)
- Event deduplication within a configurable window
- Path fuzzy matching with tilde expansion and prefix matching
- Confidence scoring (exact, prefix, substring matches)

### Uncorrelated Activity Detection

OS events from agent processes that cannot be linked to any MCP request are flagged as "uncorrelated" with severity ratings:

| Activity | Severity |
|----------|----------|
| External network connection | Critical |
| Process execution | High |
| File access to sensitive paths (.ssh, .aws, keychains) | High |
| File access outside project directory | Medium |
| File access inside project directory | Low |

### 4-Layer Agent Identification

The process tree now identifies AI agent processes using four layers:

1. **Tagged** -- processes explicitly registered by the MCP proxy
2. **Signature** -- known client signatures (Claude Code, Cursor, Windsurf, etc.)
3. **Heuristic** -- detection based on process name, path, and command-line patterns
4. **Ancestry** -- processes whose parent chain leads to a known agent

PID recycling protection prevents stale agent registrations from misidentifying new processes.

### Menu Bar App

A native macOS menu bar application (SwiftUI) provides:
- Color-coded status indicator (green/yellow/red)
- Prompt approval window with keyboard shortcuts (D=Deny, A=Allow)
- Real-time alerts for blocked events and uncorrelated activity
- Subsystem health dashboard

### Unified Daemon

The daemon now orchestrates all subsystems with graceful startup:
- Process tree with configurable refresh interval
- eslogger with FDA detection and crash recovery
- FSEvents with sensitivity classification and debouncing
- Correlation engine with configurable time windows
- Event router forwarding to audit, UI, and analysis sinks
- Hot-reload for policy and sensor configuration files

### Multi-Proxy Architecture

The daemon supports multiple MCP proxy instances, each managing a separate MCP server. Server PIDs are registered for per-server correlation.

### Enhanced FSEvents

The filesystem watcher now includes:
- **Sensitivity tiers** -- classifies file changes as Critical, High, Medium, or Low based on path
- **Debouncing** -- collapses rapid changes to the same file
- **Rate limiting** -- prevents event storms from overwhelming the system
- **eslogger correlation** -- deduplicates events already captured by eslogger

## System Requirements

- macOS Ventura (13.0) or later
- Full Disk Access for eslogger
- sudo for running eslogger
- Rust toolchain for building from source

## Upgrading from v0.3.0

1. Build the new version: `cargo build --release`
2. Create `~/.config/clawdefender/sensor.toml` (or use defaults)
3. Grant Full Disk Access to the daemon binary (for eslogger)
4. Restart the daemon: `clawdefender daemon restart`
5. Optionally build the menu bar app: `just build-menubar`

No breaking changes to existing configuration. The sensor subsystem is enabled by default but degrades gracefully if FDA is not granted. All v0.3.0 features (MCP proxy, policy engine, SLM, swarm) continue to work unchanged.

## New configuration

Add to `~/.config/clawdefender/sensor.toml`:

```toml
[eslogger]
enabled = true
events = ["exec", "open", "close", "rename", "unlink", "connect", "fork", "exit"]
ignore_processes = ["spotlight", "mds"]
ignore_paths = ["/System/"]

[fsevents]
enabled = true
watch_paths = []

[correlation]
window_ms = 500

[process_tree]
refresh_interval_secs = 5
```

## New CLI commands

- `clawdefender daemon status` -- show subsystem health
- `clawdefender daemon sensor-config` -- display active sensor configuration
- `clawdefender doctor` -- check system readiness (FDA, eslogger, etc.)

## Known Limitations

- eslogger is NOTIFY-only: the sensor can observe but not block OS-level events
- OS-level monitoring is macOS-specific; the MCP proxy works cross-platform
- The menu bar app requires macOS 13.0+
- eslogger requires root privileges (sudo)
- PID recycling detection depends on process start_time availability

## Test Coverage

The project now includes 600+ tests across all crates, including:
- Unit tests for all sensor modules (parser, filter, process tree, correlation rules, severity)
- Integration tests for the full correlation pipeline
- Mock eslogger for testing without sudo/FDA
- Security tests for path traversal, field truncation, and injection resistance
- End-to-end proxy tests
