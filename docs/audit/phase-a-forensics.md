# Phase A: Pipeline Forensics Investigation Report

## Executive Summary

The enriched proxy events never reach the GUI Timeline because the **proxy and daemon each create their own independent `FileAuditLogger`** that both write to the same `audit.jsonl` file. However, **the proxy only writes enriched events when it actually intercepts MCP traffic** (i.e., when Claude Desktop launches the proxy binary wrapping an MCP server). The daemon independently writes session-start/session-end events on every startup/shutdown. Since the daemon is the only component that has been consistently running, only its session-start/session-end events appear in the log. The proxy has apparently never been invoked by an MCP client (Claude Desktop) during the observed period, so zero tool-call events were ever written.

**There is no pipeline break between stages 2-4. The pipeline is correctly wired. The proxy simply has not been invoked.**

However, there are secondary issues that would affect display quality even if the proxy were running. These are documented below.

---

## 1. Audit Log Analysis

### File: `~/.local/share/clawdefender/audit.jsonl`
- **Size**: 66,538 bytes, 217 lines
- **Content**: 100% session-start and session-end events
- **Zero enriched events**: No tool_call, resource_read, or any MCP-intercepted events
- **Source field**: Always `"system"` (from FileAuditLogger's built-in session management)
- **Action field**: Always `"log"`

### Record format (every line):
```json
{
  "timestamp": "2026-02-23T...",
  "source": "system",
  "event_summary": "session-start",
  "event_details": {"session_id": "..."},
  "rule_matched": null,
  "action_taken": "log",
  "response_time_ms": null,
  "session_id": "..."
}
```

### Key observation:
- The `session_id` field appears both in `event_details` and as a top-level field
- No `server_name`, `tool_name`, `jsonrpc_method`, `classification`, or any enriched fields
- Session-end events always show `"total_logged": 0` -- confirming no events were ever logged during any session

### Other files:
- `~/.local/share/clawdefender/clawdefender.pid` -- daemon PID file
- `~/.local/share/clawdefender/clawdefender.sock` -- IPC Unix socket
- `~/.clawdefender/onboarding_complete` -- GUI onboarding flag

---

## 2. Proxy Event Output (CRITICAL)

### File: `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs`

The proxy creates its **own `FileAuditLogger`** in `StdioProxy::new()` (line 88-105):

```rust
let (audit_tx, mut audit_rx) = mpsc::channel::<AuditRecord>(1024);

let audit_log_path = default_audit_log_path();  // ~/.local/share/clawdefender/audit.jsonl
let audit_logger = Arc::new(
    FileAuditLogger::new(audit_log_path.clone(), LogRotation::default())
        .context("creating proxy audit logger")?,
);

// Background task drains audit records into the file logger
tokio::spawn(async move {
    while let Some(record) = audit_rx.recv().await {
        if let Err(e) = audit_logger.log(&record) { ... }
    }
});
```

The proxy writes enriched records via `build_enriched_audit_record()` (line 1332-1403) which populates:
- `source`: "mcp-proxy"
- `event_summary`: Human-readable label ("File Read", "Shell Command", etc.)
- `direction`: "client_to_server"
- `server_name`: Derived from the command path
- `tool_name`: Extracted from JSON-RPC params
- `arguments`: Tool call arguments
- `jsonrpc_method`: "tools/call", "resources/read", etc.
- `classification`: Risk level ("low", "medium", "high", "critical")
- `policy_action`: "allowed", "blocked", "prompted", "logged"

### Every code path that creates audit records:
1. **Classification::Log** (line 726-734): `mk_record(&event, "log", None)` via `audit_tx.try_send()`
2. **Classification::Review -> Allow** (line 796-801): `mk_record(&event, "allow", None)`
3. **Classification::Review -> Block** (line 806-820): `mk_record(&event, "block", None)`
4. **Classification::Review -> Prompt -> AllowOnce** (line 926-928): `mk_rec(&event, "allow_once", None)`
5. **Classification::Review -> Prompt -> AllowSession** (line 934-941): `mk_rec(&event, "allow_session", None)`
6. **Classification::Review -> Prompt -> AddPolicy** (line 946-953): `mk_rec(&event, "add_to_policy", None)`
7. **Classification::Review -> Prompt -> Deny/Timeout** (line 955-968): `mk_rec(&event, "deny", None)`
8. **Classification::Review -> Log** (line 1097-1105): `mk_record(&event, "log", None)`
9. **Server->Client relay** (line 370-376): `build_audit_record(&event, "forward", None)`
10. **SLM analysis** (line 988-991): supplementary record with `slm_analysis`
11. **Swarm analysis** (line 1061-1067): record with `swarm_analysis`

**All paths use `audit_tx.try_send()` which goes to the proxy's own FileAuditLogger writing to the same `audit.jsonl`.**

### The proxy also writes its own session-start/session-end:
The `FileAuditLogger::new()` constructor automatically logs a session-start record (logger.rs:208-243), and `Drop` logs session-end (logger.rs:366-409). This means each proxy invocation creates its own session pair -- but since the proxy was never invoked, none appear.

---

## 3. Daemon Event Input

### File: `crates/clawdefender-daemon/src/lib.rs`

The daemon creates its **own separate `FileAuditLogger`** (line 123-125):
```rust
let audit_logger = FileAuditLogger::new(
    config.audit_log_path.clone(),
    config.log_rotation.clone()
)?;
```

The daemon's `run()` method (line 588+) sets up:
1. An `audit_tx`/`audit_rx` channel (line 606)
2. An audit writer task (line 678-685) that drains the channel into `audit_logger.log()`
3. The sensor subsystem (process tree, eslogger, FSEvents) feeds into a CorrelationEngine
4. The EventRouter receives correlated events and sends them to the audit channel

### Who generates session-start/session-end?
The `FileAuditLogger::new()` constructor automatically writes a session-start record. The `Drop` implementation writes session-end. Every time the daemon starts, it creates a FileAuditLogger which generates a session-start. When the daemon shuts down, the logger's Drop generates session-end.

### Does the daemon listen for proxy events?
**NO.** The daemon and proxy are **completely independent processes**:
- The proxy is a standalone binary (`clawdefender-mcp-proxy`) launched by Claude Desktop
- The daemon is a separate binary (`clawdefender-daemon`) launched by the Tauri app or launchd
- They share no IPC channel for audit events
- They both independently write to the same `~/.local/share/clawdefender/audit.jsonl`

The IPC socket (`clawdefender.sock`) only supports `status`, `reload`, `shutdown`, and `GuardRequest` messages -- **NOT** audit event forwarding.

---

## 4. GUI Event Stream (event_stream.rs)

### File: `clients/clawdefender-app/src-tauri/src/event_stream.rs`

The GUI polls `audit.jsonl` every 500ms:
1. On startup: backfills last 100 lines
2. Main loop: seeks to last known position, reads new lines
3. Parses each line as `DaemonAuditRecord`
4. Converts to `AuditEvent` via `to_audit_event()`
5. Emits Tauri events via `process_event()`

### Field mapping (`to_audit_event`, line 155-207):
| audit.jsonl field | AuditEvent field | Mapping |
|---|---|---|
| `source` | `event_type` | Direct copy |
| `server_name` | `server_name` | Default "unknown" |
| `tool_name` | `tool_name` | Direct copy (Option) |
| `event_summary` | `action` | Direct if non-empty and not session-start/end |
| `policy_action` ?? `action_taken` | `decision` | Uses policy_action first |
| `classification` | `risk_level` | Normalized via `normalize_risk_level()` |
| `arguments` | `resource` | Extracts path/uri/url/command |
| (computed) | `details` | `build_human_details()` |

### The mapping is correct for enriched proxy records:
- If the proxy writes `source: "mcp-proxy"`, `tool_name: "read_file"`, `server_name: "filesystem"`, `event_summary: "File Read"`, `classification: "low"`, `policy_action: "allowed"` -- the GUI would display it correctly.

---

## 5. Root Cause Analysis

### Primary Issue: Proxy never invoked

The 217 session events in audit.jsonl are all from the **daemon** being started and stopped repeatedly. The proxy binary has never been invoked by Claude Desktop (or any MCP client) during the observed period.

**Evidence:**
- Every session-end shows `"total_logged": 0` (no events were ever logged in any session)
- All events have `"source": "system"` (FileAuditLogger session management, not "mcp-proxy")
- No events with `server_name`, `tool_name`, or any enriched fields

### Why the proxy would not be invoked:
For the proxy to intercept MCP traffic, Claude Desktop's config must be modified to launch `clawdefender-mcp-proxy -- <original-server-command>` instead of directly launching the MCP server. This wrapping configuration may not have been applied.

### Secondary Issues (would affect display quality if proxy runs):

1. **Duplicate session records**: Both daemon and proxy create their own `FileAuditLogger`, each writing session-start/session-end to the same file. This means the GUI would see interleaved session events from both sources with different session IDs.

2. **Concurrent write safety**: Both daemon and proxy open the same file with `O_APPEND`. While `O_APPEND` is atomic for small writes on most filesystems, the `BufWriter` in FileAuditLogger may split writes across multiple `write()` syscalls, potentially interleaving partial JSON lines.

3. **The `FileAuditLogger` in the proxy creates its own session-start on construction**: This session-start has `source: "system"` (not `"mcp-proxy"`), making it indistinguishable from daemon session-start events.

---

## 6. Field Mapping Verification

When the proxy DOES write enriched events, the field names match perfectly between:
- **Proxy output** (`AuditRecord` struct in `audit/mod.rs`)
- **audit.jsonl format** (serialized by serde_json)
- **event_stream.rs parsing** (`DaemonAuditRecord` struct)
- **TypeScript interfaces** (`AuditEvent` in `types/index.ts`)

There is **no field name mismatch**. The `DaemonAuditRecord` struct uses `#[serde(default)]` on all optional fields, making it forward-compatible with any subset of fields.

---

## 7. Pipeline Architecture Diagram

```
Claude Desktop                    Proxy Binary                     audit.jsonl
     |                    (only runs when CD launches it)              |
     |-- stdin/stdout --> [clawdefender-mcp-proxy]                    |
                            |                                          |
                            |-- FileAuditLogger::new() -----> session-start
                            |-- intercept JSON-RPC                     |
                            |-- build_enriched_audit_record()          |
                            |-- audit_tx.try_send() ---------> enriched events
                            |-- Drop --------------------------> session-end
                                                                       |
Daemon Binary                                                          |
(always running)                                                       |
     |-- FileAuditLogger::new() ----------------------------> session-start
     |-- sensor subsystem -> EventRouter -> audit_tx -------> OS events
     |-- Drop ----------------------------------------------> session-end
                                                                       |
GUI (Tauri App)                                                        |
     |-- event_stream.rs polls audit.jsonl <-----------------------+
     |-- to_audit_event() -> process_event() -> Timeline
```

---

## 8. Recommended Fix Approach

### Immediate (verify proxy invocation):
1. **Check Claude Desktop config** -- verify MCP servers are wrapped with `clawdefender-mcp-proxy -- <cmd>`
2. **Test manually**: Run `clawdefender-mcp-proxy -- npx @anthropic-ai/mcp-server-demo` and send a tools/call request
3. **Check proxy logs**: The proxy logs to stderr. Run with `RUST_LOG=debug` to see if it's being invoked at all.

### If the proxy IS being invoked but events still don't appear:
1. Check if `default_audit_log_path()` resolves to the same path the GUI watches
2. Check file permissions on `~/.local/share/clawdefender/audit.jsonl`
3. Check if the BufWriter flush is happening (the proxy's background task uses `audit_logger.log()` which goes through the channel-based writer)

### Architectural improvements:
1. **Single audit writer**: Have only the daemon own the FileAuditLogger. The proxy should send events to the daemon via the IPC socket instead of writing directly to the file.
2. **Event source tagging**: Session-start events from proxy vs daemon should have different source fields (e.g., "proxy-system" vs "daemon-system") for disambiguation.
3. **Real-time event forwarding**: Instead of file polling, consider using the IPC socket or a named pipe for real-time event delivery from proxy to daemon to GUI.

---

## 9. Summary of Findings

| Question | Answer |
|---|---|
| Where does the proxy write enriched events? | To `~/.local/share/clawdefender/audit.jsonl` via its own FileAuditLogger |
| Why do only session-start/end events appear? | The proxy has never been invoked. All 217 events are from daemon starts/stops. |
| Does the proxy connect to the daemon? | **NO**. They are independent processes sharing a log file. |
| Is there a JSON format mismatch? | **NO**. Field names match across all layers. |
| What is the EXACT break point? | **Stage 1**: The MCP client (Claude Desktop) is not launching the proxy. |
| Recommended fix? | 1) Verify Claude Desktop MCP server wrapping config. 2) Consider IPC-based event forwarding instead of shared file. |
