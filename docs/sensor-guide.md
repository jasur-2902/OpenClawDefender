# Sensor Guide

The OS-level sensor monitors system activity from AI agent processes using macOS Endpoint Security (`eslogger`) and FSEvents.

## Prerequisites

- **macOS 13.0 (Ventura)** or later
- **Full Disk Access** for the ClawDefender daemon process
- **sudo access** for running `eslogger`

## Setup

### 1. Check system readiness

```bash
clawdefender doctor
```

This checks for:
- macOS version compatibility
- Full Disk Access (FDA) grant status
- `eslogger` binary availability (`/usr/bin/eslogger`)

### 2. Grant Full Disk Access

1. Open **System Settings** > **Privacy & Security** > **Full Disk Access**
2. Click the lock to make changes
3. Add the ClawDefender daemon binary (or Terminal.app if running from source)
4. Restart the daemon

### 3. Start the daemon

```bash
clawdefender daemon start
```

The sensor subsystem starts automatically. If FDA is not granted, the daemon logs a warning and continues without eslogger (the MCP proxy still works).

## Configuration

Edit `~/.config/clawdefender/sensor.toml`:

```toml
[eslogger]
enabled = true
events = ["exec", "open", "close", "rename", "unlink", "connect", "fork", "exit"]
channel_capacity = 10000
ignore_processes = ["spotlight", "mds", "mds_stores"]
ignore_paths = ["/System/", "/usr/share/"]

[fsevents]
enabled = true
watch_paths = ["/Users/you/Projects"]

[correlation]
window_ms = 500

[process_tree]
refresh_interval_secs = 5
```

### Configuration options

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `eslogger` | `enabled` | `true` | Enable/disable eslogger |
| `eslogger` | `events` | 8 event types | ES event types to subscribe to |
| `eslogger` | `channel_capacity` | `10000` | Internal buffer size |
| `eslogger` | `ignore_processes` | `[]` | Process names to filter out |
| `eslogger` | `ignore_paths` | `[]` | Path prefixes to filter out |
| `fsevents` | `enabled` | `true` | Enable/disable FSEvents |
| `fsevents` | `watch_paths` | `[]` | Directories to watch (empty = defaults) |
| `correlation` | `window_ms` | `500` | Time window for matching MCP to OS events |
| `process_tree` | `refresh_interval_secs` | `5` | Process tree refresh interval |

## Reading Correlation Data

Correlated events appear in the audit log at `~/.local/share/clawdefender/audit.jsonl`. Each correlation record includes:

- **Matched events**: MCP tool call linked to one or more OS events
- **Uncorrelated events**: OS events from agent processes with no matching MCP request

Query correlation events:

```bash
clawdefender log --source correlation
```

### Correlation rules

The engine uses 4 matching rules:

1. **ToolCall to Exec** -- MCP `tools/call` for shell tools (`run_command`, `bash`, `execute`) matched to eslogger `exec` events
2. **ResourceRead to Open** -- MCP `resources/read` with `file://` URI matched to eslogger `open` events
3. **FileTool to FileOp** -- MCP `tools/call` for file tools (`read_file`, `write_file`) matched to file operations
4. **NetworkTool to Connect** -- MCP `tools/call` for network tools (`fetch`, `curl`) matched to `connect` events

## Responding to Uncorrelated Activity

Uncorrelated events are OS-level actions from agent processes that have no corresponding MCP request. These may indicate:

- An agent bypassing MCP to access resources directly
- A child process taking unexpected actions
- Legitimate activity not captured by the MCP proxy

Severity levels for uncorrelated events:

| Activity | Severity | Example |
|----------|----------|---------|
| External network connection | Critical | Agent process connects to unknown IP |
| Process execution | High | Agent spawns `/usr/bin/curl` without MCP tool call |
| File access outside project | Medium | Agent reads `/etc/hosts` |
| File access inside project | Low | Agent reads project source files |
| Loopback network | Low | Agent connects to `127.0.0.1` |
| File close / fork / exit | Info | Normal process lifecycle |

## Troubleshooting

### eslogger not starting

- Verify FDA is granted: check System Settings > Privacy & Security > Full Disk Access
- Check the daemon log: `clawdefender log --source eslogger`
- Try running eslogger manually: `sudo eslogger exec open connect`

### FDA not granted

The daemon starts without the sensor when FDA is missing. The audit log will contain:

```
eslogger: unavailable (Full Disk Access not granted)
```

Grant FDA and restart the daemon to enable the sensor.

### High CPU usage

If the sensor uses too much CPU:

1. Reduce monitored event types in `sensor.toml`
2. Add noisy processes to `ignore_processes`
3. Add system paths to `ignore_paths`
4. Increase the correlation window (`window_ms`) to reduce tick frequency
5. The built-in resource monitor will log warnings if limits are approached

### Process tree too large

If you see warnings about process tree size:

```
process tree at capacity, dropping new entry
```

This is a safety limit (10,000 processes). It should not occur in normal usage. If it does, check for runaway fork activity.
