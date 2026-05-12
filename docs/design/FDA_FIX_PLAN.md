# FDA Detection Fix — Root Cause Analysis & Action Plan

## Root Cause

The `get_sensor_health` command returns `fda_granted: true` when FDA is **not** granted because of a flawed fallback chain:

```rust
let fda_granted = eslogger_running       // pgrep -x eslogger (unreliable)
    || tcc_probe_ok                      // read_dir(~/Library/Safari) (fails in dev mode)
    || (daemon_running && events_flowing); // ALWAYS TRUE — fsevents writes to audit.jsonl without FDA
```

**Why each strategy fails:**

| Strategy | Problem |
|----------|---------|
| `pgrep -x eslogger` | eslogger runs via `sudo`, may not be visible to GUI process; also doesn't run at all when FDA is missing |
| `read_dir(~/Library/Safari)` | Probes TCC for the **Tauri GUI binary**, not the daemon. In dev mode, the debug binary has no TCC entry. `~/Library/Safari` may not exist on all systems. |
| `daemon_running && events_flowing` | FSEvents **always runs** (no FDA needed) and writes to `audit.jsonl`, making `events_flowing` true regardless of FDA |

**The same false-positive exists in `score/factors.rs:337`** which checks `audit.jsonl` exists with content — true even with only fsevents.

## Key Discovery: audit.jsonl Has a `source` Field

Every record in `audit.jsonl` has a `source` field that distinguishes event origins:

- `"eslogger"` — from Endpoint Security (requires root + FDA)
- `"fsevents"` — from FSEvents/notify (no special permissions)
- `"correlation"` — merged events from correlation engine
- `"proxy"` / `"mcp-proxy"` — from MCP proxy

**If recent audit records contain `source: "eslogger"`, FDA is truly granted.** This is the most reliable signal because:
1. The **daemon** decides whether to start eslogger based on its own FDA check
2. If eslogger events appear in the log, the daemon successfully started eslogger
3. No false positives possible — eslogger cannot produce events without FDA

## The Fix

### Strategy: Check audit.jsonl for eslogger-sourced events

Replace the unreliable 3-way OR with a single, reliable check:

1. **Primary signal**: Scan the last N lines of `audit.jsonl` for any record with `source: "eslogger"` or `source: "correlation"` (correlation only happens when eslogger feeds events). If found within the last 120 seconds, `fda_granted = true`.
2. **Fallback signal**: Keep `pgrep -x eslogger` as a secondary check (covers the case where eslogger just started and hasn't written events yet).
3. **Remove**: The `tcc_probe_ok` directory probe (unreliable across code-signing contexts) and the `daemon_running && events_flowing` fallback (fundamentally broken).

### Files to Change

#### 1. `src-tauri/src/commands.rs` — `get_sensor_health` (lines 9492-9513)

Replace the FDA detection block with:

```rust
// FDA granted: check if eslogger events appear in recent audit data.
// The daemon starts eslogger only when it has FDA, so eslogger-sourced
// records in audit.jsonl are definitive proof.
let eslogger_running = std::process::Command::new("pgrep")
    .args(["-x", "eslogger"])
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false);

let has_eslogger_events = audit_has_eslogger_source(&audit_path);

let fda_granted = eslogger_running || has_eslogger_events;
```

Add helper function:

```rust
/// Scan the tail of audit.jsonl for any recent eslogger-sourced events.
/// Returns true if eslogger events were written in the last 120 seconds.
fn audit_has_eslogger_source(audit_path: &std::path::Path) -> bool {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    let file = match std::fs::File::open(audit_path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut reader = BufReader::new(file);

    // Read last 32KB (enough for ~100-200 recent records)
    if file_len > 32_768 {
        let _ = reader.seek(SeekFrom::End(-32_768));
        // Skip partial first line
        let mut skip = String::new();
        let _ = reader.read_line(&mut skip);
    }

    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 - 120)
        .unwrap_or(0);

    let mut found = false;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        // Quick string check before full parse for performance
        if !line.contains("\"eslogger\"") {
            continue;
        }
        // Parse to verify it's the source field and check timestamp
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            if v.get("source").and_then(|s| s.as_str()) == Some("eslogger") {
                // Optionally check timestamp freshness
                if let Some(ts) = v.get("timestamp").and_then(|t| t.as_str()) {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                        if dt.timestamp() >= cutoff {
                            found = true;
                            break;
                        }
                    }
                } else {
                    // No timestamp but source is eslogger — still counts
                    found = true;
                    break;
                }
            }
        }
    }

    found
}
```

#### 2. `src-tauri/src/score/factors.rs` — `compute_system_visibility` (lines 334-341)

Replace:
```rust
let has_fda = audit_path.exists() && {
    std::fs::metadata(&audit_path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
};
```

With:
```rust
let has_fda = crate::commands::audit_has_eslogger_source(&audit_path);
```

(Make `audit_has_eslogger_source` public.)

#### 3. Frontend — No changes needed

The frontend already uses `h.fda_granted` from `get_sensor_health`. Once the backend returns the correct value, all UI components (PermissionBanner, SetupPermissions, Onboarding, Settings) will work correctly.

## Dev Mode Behavior

With this fix:
- **FDA not granted (dev mode)**: eslogger won't start → no `"eslogger"` records → `fda_granted = false` → banner shows (correct)
- **FDA granted (dev mode)**: daemon detects FDA → starts eslogger → `"eslogger"` records appear → `fda_granted = true` → banner hides (correct)
- **FDA granted (production)**: same as above, `pgrep` may also work as secondary signal
- **Fresh install (no audit.jsonl yet)**: no eslogger events → `fda_granted = false` → banner shows (correct)

## Remaining Issue: eslogger Parser Format Mismatch

The eslogger event parser (`crates/clawdefender-sensor/src/eslogger/parser.rs`) expects a **simplified format**:
```json
{"event_type": "exec", "process": {"pid": 1234, "ppid": 1, "executable": "/usr/bin/node"}, ...}
```

But the real macOS eslogger outputs a **much more complex format**:
```json
{"version":10, "event_type":13, "process": {"audit_token": {"pid": 1234, ...}, "executable": {"path": "..."}, ...}, "event": {"create": {"destination": ...}}}
```

Key differences:
- `event_type` is a numeric enum (13 = create), not a string name
- Process info is nested deeper (`process.audit_token.pid` not `process.pid`)
- Executable path is at `process.executable.path` not `process.executable`
- Event details are in `event.create.destination` not `event.target_path`

**This needs a separate task** to rewrite the parser to handle the actual macOS eslogger NDJSON format. The `EsloggerEvent` struct in `types.rs` and the `parse_event` function both need updating.

## Test Plan

1. **Build**: `cargo tauri dev` — verify no compilation errors
2. **FDA not granted**: Revoke FDA in System Settings → relaunch app → verify:
   - Home/Activity/MyTools show amber banner
   - SetupPermissions page shows red X for FDA
   - Settings shows amber dot + "Not granted"
   - Score factor shows "partial" (5 points)
3. **FDA granted**: Grant FDA → relaunch daemon → wait for eslogger events → verify:
   - Banner auto-dismisses (10s poll)
   - SetupPermissions shows green success
   - Settings shows green dot + "Granted"
   - Score factor shows "full" (15 points)
4. **Edge case**: Delete audit.jsonl → verify `fda_granted = false` until eslogger writes new events
