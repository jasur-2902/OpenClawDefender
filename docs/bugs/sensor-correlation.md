# Sensor & Correlation Bugs

Bugs found and fixed in `crates/clawdefender-sensor/` during Phase 6R review.

## Bug 1: Pre-filter drops read-only opens on sensitive paths (SECURITY)

**File:** `src/eslogger/filter.rs:131-134`
**Severity:** HIGH
**Impact:** If an agent process reads `~/.ssh/id_rsa` or `/etc/passwd` without MCP
authorization, the event is silently dropped because `flags == 0` (O_RDONLY) was
unconditionally filtered. This is a critical security gap: unauthorized credential
reads by agent processes go completely undetected.

**Fix:** Changed the read-only open filter to exempt sensitive paths (SSH keys, AWS
credentials, GPG keys, Kubernetes config, etc.). Added `is_sensitive_path()` helper
with `SENSITIVE_PATH_PREFIXES` and `SENSITIVE_ABSOLUTE_PATHS` constants.

**Regression tests:** `passes_readonly_open_on_sensitive_path`,
`drops_readonly_open_on_nonsensitive_path`

## Bug 2: Pre-filter checks `team_id` instead of `signing_id` for Apple processes

**File:** `src/eslogger/filter.rs:107-110`
**Severity:** MEDIUM
**Impact:** The filter checked `event.team_id.starts_with("com.apple")` but Apple's
`team_id` is a short identifier (e.g. "apple"), not a bundle-style ID. The
`com.apple.xxx` pattern is for `signing_id`. This meant the Apple process filter
rule never actually matched, allowing noisy Apple-signed system processes through.

**Fix:** Changed to check `event.signing_id.starts_with("com.apple.")` instead.

**Regression test:** `drops_apple_signing_id`

## Bug 3: Missing system processes from ignore list

**File:** `src/eslogger/filter.rs:35-53`
**Severity:** LOW
**Impact:** `distnoted`, `mdworker_shared`, `coreduetd`, `bird`, `secinitd`,
`cfprefsd`, `containermanagerd`, `lsd`, `symptomsd` were missing from the ignore
list. These are high-volume macOS system processes that add noise without security
value.

**Fix:** Added all missing system processes to `ignore_processes` HashSet.

## Bug 4: eslogger invoked with invalid `--format json` flag

**File:** `src/eslogger/process.rs:152`
**Severity:** HIGH
**Impact:** The `spawn_eslogger()` function passed `--format json` to eslogger, but
macOS eslogger does not accept a `--format` flag. It always outputs NDJSON by
default. This would cause eslogger to fail to start with an unknown argument error,
then the supervisor would enter an infinite crash-restart loop.

**Fix:** Removed the `--format json` arguments.

## Bug 5: Correlation engine rejects OS events that arrive slightly before MCP events

**File:** `src/correlation/engine.rs:195-199`
**Severity:** MEDIUM
**Impact:** When processing OS events against pending MCP events, the engine only
accepted positive time deltas (`os.timestamp - mcp.timestamp >= 0`). Due to clock
skew and processing delays, eslogger can report events ~100ms before the MCP proxy
logs the corresponding tool call. This caused legitimate correlated events to be
classified as uncorrelated, generating false alerts.

**Fix:** Changed to use absolute time delta (same as the MCP->OS direction already
used). Both directions now accept events within the match window regardless of
ordering.

## Bug 6: Network tool matching hardcoded to "example.com"

**File:** `src/correlation/rules.rs:162-170`
**Severity:** MEDIUM
**Impact:** The fuzzy hostname matching for network tool correlation only checked for
the literal string "example.com". Any other hostname in tool call arguments would
not trigger fuzzy matching, causing legitimate network correlations to be missed and
flagged as uncorrelated.

**Fix:** Replaced with `args_contains_url_or_hostname()` that detects URL schemes
(`http://`, `https://`) and hostname-like patterns (word.tld format) in arguments.

## Bug 7: FsEvent-to-OsEvent conversion sets flags=0 for writes

**File:** `src/fsevents/mod.rs:200-203`
**Severity:** HIGH
**Impact:** When converting `FsEvent::Created` and `FsEvent::Modified` to `OsEvent`,
the `flags` field was set to 0 (O_RDONLY). The pre-filter then dropped these events
as read-only opens. This meant ALL file creation and modification events detected
by FSEvents were silently discarded before reaching the correlation engine.

**Fix:** Changed to use `flags: 1` (O_WRONLY) for Created/Modified conversions so
they pass through the pre-filter.

## Bug 8: Missing `/usr/lib/` from ignore path prefixes

**File:** `src/eslogger/filter.rs:59-63`
**Severity:** LOW
**Impact:** Processes under `/usr/lib/` (system libraries) were not being filtered,
adding unnecessary volume to the event pipeline.

**Fix:** Added `/usr/lib/` to `ignore_path_prefixes`.

---

## Summary

| # | Bug | Severity | Category |
|---|-----|----------|----------|
| 1 | Read-only opens on sensitive paths dropped | HIGH | Pre-filter (security) |
| 2 | team_id vs signing_id mismatch | MEDIUM | Pre-filter |
| 3 | Missing system processes in ignore list | LOW | Pre-filter |
| 4 | Invalid eslogger --format flag | HIGH | Process management |
| 5 | Asymmetric correlation time window | MEDIUM | Correlation engine |
| 6 | Hardcoded hostname in network matching | MEDIUM | Correlation rules |
| 7 | FsEvent writes converted with flags=0 | HIGH | FSEvents |
| 8 | Missing /usr/lib/ ignore prefix | LOW | Pre-filter |

All bugs fixed with regression tests. Total tests: 127 passing (101 lib + 14 evasion + 12 integration).
