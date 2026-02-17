# Sensor Security Model

This document describes the security properties, trust boundaries, evasion
mitigations, and resource limits of the ClawDefender sensor layer.

## Privilege Model

| Component | Runs as | Why |
|---|---|---|
| `eslogger` child process | `root` (via `sudo`) | Endpoint Security requires root |
| Sensor daemon | Current user | Only needs to read eslogger stdout |
| FSEvents watcher | Current user | `notify` crate, no special privileges |
| Process tree (sysinfo) | Current user | Reads `/proc`-equivalent via `sysinfo` |
| Menu bar UI | Current user | Standard AppKit application |

The `sudo eslogger` invocation is the only elevated operation. The sensor daemon
itself runs unprivileged and communicates with eslogger over a pipe (stdout).

## Data Access

The sensor observes **metadata only**:

- **Process metadata**: PID, PPID, executable path, signing identity, team ID,
  command-line arguments, start time.
- **File paths**: Which files are opened, closed, renamed, deleted, or
  chmod-ed. **File contents are never read.**
- **Network destinations**: Remote address and port for `connect()` calls.
  **Network traffic/payloads are never captured.**

## Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│  Kernel (Endpoint Security framework)           │  TRUSTED
│  Provides: eslogger NDJSON on stdout            │
└────────────────────┬────────────────────────────┘
                     │ pipe (stdout)
┌────────────────────▼────────────────────────────┐
│  eslogger output parser                         │  UNTRUSTED INPUT
│  - Max line length: 1 MB                        │
│  - Field truncation: 4096 bytes                 │
│  - Null byte stripping                          │
│  - Unicode NFC normalization                    │
│  - Path canonicalization (.. resolution)        │
└────────────────────┬────────────────────────────┘
                     │ validated OsEvent
┌────────────────────▼────────────────────────────┐
│  EventPreFilter                                 │  FILTERED
│  - Drop system processes (HashSet)              │
│  - Drop Apple team IDs                          │
│  - Debounce rapid duplicates                    │
│  - Drop read-only opens                         │
└────────────────────┬────────────────────────────┘
                     │ filtered OsEvent
┌────────────────────▼────────────────────────────┐
│  Correlation Engine + Process Tree              │  ATTRIBUTED
│  - PID+start_time verification                  │
│  - 4-layer agent identification                 │
│  - Transitive ancestry tracking                 │
└─────────────────────────────────────────────────┘
```

### Key principle: eslogger output is treated as untrusted

Even though eslogger is a kernel-backed tool, its NDJSON output passes through
pipes and text parsing. All string fields are:

1. Checked for null bytes (truncated at first `\0`)
2. Normalized to Unicode NFC
3. Path-canonicalized (logical `..` resolution without filesystem access)
4. Truncated to 4096 bytes maximum
5. Rejected entirely if the JSON line exceeds 1 MB

## Evasion Risks and Mitigations

### PID Recycling

**Risk**: Process exits, OS reuses PID for a different process. A stale agent
registration could misattribute events.

**Mitigation**: Every tagged agent registration records the process start_time.
On lookup, `is_agent()` and `get_tagged_agent()` cross-reference PID +
start_time. If they don't match, the registration is rejected. `handle_exit()`
cleans up all state for exited PIDs.

### Unicode Normalization (NFC vs NFD)

**Risk**: macOS HFS+ uses NFD for filenames, but MCP tools may send NFC paths.
An attacker could craft a filename in NFD that doesn't match the NFC version
in the MCP event, causing the correlation engine to miss the match.

**Mitigation**: All paths are normalized to NFC before entering the pipeline.
The `sanitize_path()` function applies `unicode-normalization` crate's NFC
transformation. Both MCP and OS event paths go through this normalization.

### Path Traversal

**Risk**: eslogger reports literal `..` components (e.g.,
`/Users/dev/Projects/../../.ssh/id_rsa`). If the path is not canonicalized,
sensitivity classification may incorrectly rate a critical path as Medium.

**Mitigation**: `sanitize_path()` performs logical canonicalization, resolving
`.` and `..` components without filesystem access. After canonicalization, the
path is classified correctly.

### Symlink Evasion

**Risk**: An agent creates a symlink from a project directory to a sensitive
location. eslogger reports the symlink path, not the resolved target.

**Mitigation**: Partial. eslogger typically reports the real path for most ES
events. FSEvents may report the symlink path. For full mitigation, the
correlation engine cross-references both eslogger and FSEvents observations.
Future work: add `std::fs::canonicalize()` for high-sensitivity paths (with
appropriate error handling for deleted paths).

### Timing Evasion

**Risk**: An agent performs a file operation before the correlation window
opens, so the OS event is not matched to the MCP event.

**Mitigation**: The correlation engine maintains a sliding window of OS events
that starts **before** MCP events are forwarded. The window is configurable
(default 500ms) and events are buffered in both directions: MCP events wait for
matching OS events, and OS events are retained for correlation with future MCP
events.

### Multi-Process Evasion

**Risk**: An agent forks a child, which forks a grandchild, hoping transitive
identification breaks at some depth.

**Mitigation**: Layer 4 of the agent identification system walks the full
process ancestry (up to 100 levels). If any ancestor is a tagged, known, or
heuristic-detected agent, the descendant inherits agent status.

## Performance Impact

The sensor is designed to have minimal impact on the user's system:

- **eslogger pre-filter** drops 90-95% of events before they reach the
  pipeline, based on system process names, Apple signing IDs, and path prefixes.
- **Debouncing** coalesces rapid duplicate events (100ms window for eslogger,
  200ms for FSEvents).
- **Rate limiting** activates 1-in-N sampling if events exceed 500/sec.
- **Process tree refresh** uses sysinfo and runs on a configurable interval
  (default 5 seconds), not on every event.
- **Channel backpressure**: If the event channel fills up (10,000 capacity),
  events are dropped rather than blocking eslogger.

Typical steady-state resource usage: ~10-30 MB RSS, <1% CPU.

## Fail-Open Design

The sensor follows a **fail-open** philosophy:

- If eslogger crashes or loses FDA, MCP operations continue unmonitored.
  The supervisor loop restarts eslogger with exponential backoff.
- If the event channel fills up, new events are dropped (not blocking).
- If the process tree refresh fails, the stale tree is used until the next
  successful refresh.
- If FSEvents monitoring fails, eslogger-only mode continues.

This ensures that sensor failures never block the user's AI agent workflow.
The trade-off is that brief monitoring gaps are possible during recovery.

## Resource Limits

| Resource | Default Limit | Rationale |
|---|---|---|
| Event channel capacity | 10,000 | Prevents unbounded memory growth if consumer is slow |
| MCP correlation window | 500 events | Bounds memory for pending MCP event matching |
| OS correlation window | 5,000 events | Bounds memory for OS event sliding window |
| Process tree size | 10,000 entries | Prevents DoS via process fork bomb |
| Debounce map entries | 10,000 | Cleaned up periodically; capped to prevent unbounded growth |
| Memory warning threshold | 100 MB RSS | Logs warning when sensor process exceeds this |
| JSON line max length | 1 MB | Rejects malformed/oversized eslogger output |
| String field max length | 4,096 bytes | Truncates oversized path or identity fields |

The `ResourceMonitor` periodically checks process RSS and logs warnings when
the threshold is exceeded. All limits are configurable via `ResourceLimits`.
