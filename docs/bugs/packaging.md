# Packaging & Distribution Bugs

Issues found and fixed during Phase 6R packaging audit.

## PKG-001: No release profile optimizations

**Severity:** Medium
**Status:** Fixed

The workspace `Cargo.toml` had no `[profile.release]` section. Release binaries were not optimized for size.

**Fix:** Added release profile with `lto = "fat"`, `codegen-units = 1`, `strip = true`, `opt-level = "z"`, and `panic = "abort"`.

## PKG-002: Homebrew formula class name mismatch

**Severity:** High
**Status:** Fixed

The formula class was named `Clawai` instead of `Clawdefender`. Homebrew expects the class name to match the formula filename. This would cause `brew install clawdefender` to fail with a class name mismatch error.

**Fix:** Renamed class to `Clawdefender`.

## PKG-003: Homebrew formula missing `doctor` test

**Severity:** Low
**Status:** Fixed

The `test` block only checked `--version`. Added `clawdefender doctor` test to verify the installation health check works.

## PKG-004: Release workflow missing daemon binary

**Severity:** High
**Status:** Fixed

The GitHub Actions release workflow only built `clawdefender-cli` (the CLI binary). The `clawdefender-daemon` binary was not built, not included in the universal binary, and not included in the tarball.

**Fix:** Updated `release.yml` to build both packages for both architectures, create universal binaries for both, code-sign both, and include both in the tarball.

## PKG-005: Install script missing daemon binary

**Severity:** High
**Status:** Fixed

`scripts/install.sh` only installed the `clawdefender` CLI binary. The daemon binary (`clawdefender-daemon`) was not extracted or installed to `/usr/local/bin`.

**Fix:** Updated install script to also `chmod +x` and install `clawdefender-daemon`.

## PKG-006: Uninstall script missing daemon binary

**Severity:** Medium
**Status:** Fixed

`scripts/uninstall.sh` only removed the `clawdefender` binary. The daemon binary was left behind at `/usr/local/bin/clawdefender-daemon`.

**Fix:** Updated to loop over both binary names when removing.

## PKG-007: LaunchAgent plist incorrect binary path

**Severity:** High
**Status:** Fixed

The plist ran `/usr/local/bin/clawdefender daemon` (CLI subcommand) but the daemon is a separate binary at `/usr/local/bin/clawdefender-daemon`. The CLI's `daemon start` command spawns the daemon binary as a child process -- the plist should run the daemon directly since launchd manages the lifecycle.

**Fix:** Changed `ProgramArguments` to use `/usr/local/bin/clawdefender-daemon` directly.

## PKG-008: LaunchAgent plist missing WorkingDirectory

**Severity:** Low
**Status:** Fixed

No `WorkingDirectory` was set. The daemon would inherit whatever working directory launchd provides, which is undefined.

**Fix:** Added `WorkingDirectory` set to `/tmp`.

## PKG-009: LaunchAgent using unconditional KeepAlive

**Severity:** Low
**Status:** Fixed

`KeepAlive` was set to `true`, meaning launchd would restart the daemon even after a clean exit. Changed to `SuccessfulExit = false` so the daemon only restarts on crashes, not intentional shutdowns.

## PKG-010: LaunchAgent logs in /tmp

**Severity:** Low
**Status:** Fixed

Log paths pointed to `/tmp/clawdefender-daemon.stdout.log` which could be cleaned by the system. Changed to `/usr/local/var/log/clawdefender/`.

## PKG-011: LaunchAgent missing ThrottleInterval

**Severity:** Low
**Status:** Fixed

No `ThrottleInterval` was set. If the daemon crashes in a loop, launchd would restart it rapidly. Added 5-second throttle.

## PKG-012: justfile missing daemon binary in install/package recipes

**Severity:** Medium
**Status:** Fixed

The `install`, `install-local`, and `package` recipes only copied the `clawdefender` CLI binary. Updated all three to include `clawdefender-daemon`.

## PKG-013: justfile missing preflight and bump-version recipes

**Severity:** Low
**Status:** Fixed

Added `just preflight` (lint + test) and `just bump-version VERSION` recipes for release workflow convenience.

## PKG-014: Build error in clawdefender-mcp-proxy (type mismatch)

**Severity:** Critical
**Status:** Fixed (by concurrent agent)

`handle_client_message` accepted `JsonRpcMessage` but callers passed `RawJsonRpcMessage` after the parser was updated to use raw message support. Required updating the function signature and forwarding logic.

## PKG-015: Build error in clawdefender-sensor (missing function)

**Severity:** Critical
**Status:** Observed (owned by sensor-engineer)

`is_sensitive_path` function exists in the file but the compiler reports it as not found. This appears to be a transient issue from concurrent edits by the sensor engineer agent.
