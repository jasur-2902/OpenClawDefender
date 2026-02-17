# First-Run UX Bugs and Fixes

## Summary

Audit of the first-run experience for ClawDefender CLI commands: `init`, `doctor`, `wrap`, `unwrap`, `status`, and install scripts.

---

## Bugs Found and Fixed

### 1. `doctor.rs` — No visual indicators (checkmarks/crosses)

**Severity:** Low (cosmetic)
**Before:** Used plain `ok` / `FAIL` text.
**After:** Uses Unicode checkmark, cross, and warning symbols for clear visual scanning.
**Fix:** Replaced `check()` helper with `check_pass()` returning `bool`, plus `warn()` and `hint()` helpers.

### 2. `doctor.rs` — No actionable hints for failures

**Severity:** Medium (user confusion)
**Before:** Failures just showed "FAIL" with no guidance on how to fix.
**After:** Every failure now includes a `-> hint` line with the exact command or action to resolve it.
**Examples:**
- Config dir missing -> "Run `clawdefender init`"
- Policy parse error -> "Check with a TOML validator"
- Audit dir not writable -> "Run: chmod u+w <path>"

### 3. `doctor.rs` — No macOS version check

**Severity:** Medium (silent incompatibility)
**Before:** No check for macOS version. User on macOS 12 would get cryptic eslogger failures.
**After:** Checks `sw_vers -productVersion` and warns if < 13.

### 4. `doctor.rs` — No Full Disk Access (FDA) check

**Severity:** Medium (eslogger won't work without FDA)
**Before:** No FDA check.
**After:** Probes `~/Library/Mail` as a heuristic. Warns with System Settings path if not available.

### 5. `doctor.rs` — No summary of issues/warnings

**Severity:** Low (UX)
**Before:** Just a list of checks with no conclusion.
**After:** Prints "All checks passed" or "X issue(s) found, Y warning(s)" at the end.

### 6. `init.rs` — Silent failure on audit log directory creation

**Severity:** Medium (data loss risk)
**Before:** `fs::create_dir_all(parent).ok()` — silently swallowed errors.
**After:** Prints a warning with the error message and suggests checking permissions.

### 7. `init.rs` — MCP client detection output not visually clear

**Severity:** Low (cosmetic)
**Before:** `- Claude Desktop (/path/to/config)` — functional but bland.
**After:** `Found Claude Desktop checkmark` — clearer visual feedback.

### 8. `init.rs` — Next steps not context-aware

**Severity:** Low (UX)
**Before:** Always showed the same 5 next steps regardless of detected MCP clients.
**After:** Shows different next steps depending on whether any MCP client was detected. If none found, first step is "Install an MCP client".

### 9. `status.rs` — No suggestion when daemon not running

**Severity:** Low (UX)
**Before:** Just said "not running" with no guidance.
**After:** Adds `-> Start it with: clawdefender daemon start`.

### 10. `status.rs` — No policy rule count

**Severity:** Low (UX)
**Before:** Only showed path to policy file.
**After:** Shows `Policy: /path/to/policy.toml (3 rule(s))`.

### 11. `status.rs` — Not using `detect_servers_key` for cross-client compatibility

**Severity:** Medium (functional)
**Before:** Hardcoded `mcpServers` key. Cursor uses `servers` key in some configurations.
**After:** Uses `detect_servers_key()` helper for correct key detection.

### 12. `install.sh` — No macOS version check

**Severity:** Medium (silent incompatibility)
**Before:** Checked architecture but not macOS version.
**After:** Checks `sw_vers -productVersion` and aborts if < 13 with clear message.

---

## Items Verified as Working Correctly

- `clawdefender init` is idempotent (existing files are skipped, not overwritten)
- `clawdefender init` handles missing HOME env var with clear error
- `clawdefender wrap` lists available servers when name not found
- `clawdefender wrap` shows restart instructions on success
- `clawdefender wrap` is idempotent (double-wrap is a no-op)
- `clawdefender unwrap` restores original config correctly
- `clawdefender wrap/unwrap` creates `.bak` backups before modifying
- Error messages for unknown client hint are clear
- Error messages for no MCP clients installed are clear
- `install.sh` handles architecture detection (arm64/x86_64)
- `install.sh` handles existing installations
- `install.sh` runs `clawdefender init` after install
- `install.sh` verifies SHA-256 checksum
- `uninstall.sh` offers to unwrap servers before removal
- `uninstall.sh` asks before deleting config/data dirs
- `ClawConfig::load()` returns defaults when config file doesn't exist (no crash on first run before init)

---

## Files Modified

- `clients/clawdefender-cli/src/commands/doctor.rs` — Complete rewrite with visual indicators, actionable hints, macOS version check, FDA check, summary
- `clients/clawdefender-cli/src/commands/init.rs` — Better MCP client detection output, context-aware next steps, warn on audit dir failure
- `clients/clawdefender-cli/src/commands/status.rs` — Policy rule count, daemon start hint, `detect_servers_key` compatibility
- `scripts/install.sh` — macOS version check
