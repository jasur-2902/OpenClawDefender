# Cursor & VS Code Integration Bugs

## Bug 1: Hardcoded `mcpServers` key breaks Cursor configs using `servers`

**Severity: High**
**Status: Fixed**
**Files: `clients/clawdefender-cli/src/commands/mod.rs`, `wrap.rs`, `unwrap.rs`, `doctor.rs`**

Cursor may use the `"servers"` key instead of `"mcpServers"` in its `mcp.json` config file. The wrap, unwrap, list_servers, and auto-detection code all hardcoded `"mcpServers"`, causing them to silently fail for Cursor users with the alternate format.

**Fix:** Added `detect_servers_key()` function that checks for `"mcpServers"` first, then falls back to `"servers"`. Updated all call sites: `wrap.rs`, `unwrap.rs`, `doctor.rs`, `find_client_config()`, and `list_servers()`.

**Regression tests:**
- `test_detect_servers_key_standard`
- `test_detect_servers_key_cursor_alternate`
- `test_detect_servers_key_prefers_mcp_servers`
- `test_detect_servers_key_empty_config`
- `test_detect_servers_key_non_object_value`
- `test_list_servers_with_alternate_key`
- `test_unwrap_cursor_servers_key`

---

## Bug 2: Missing Windsurf client support

**Severity: Medium**
**Status: Fixed**
**Files: `clients/clawdefender-cli/src/commands/mod.rs`**

Windsurf (by Codeium) is a popular MCP client that was not listed in `known_clients()`. Users with Windsurf could not use `--client auto` or `--client windsurf`.

**Fix:** Added Windsurf to `known_clients()` with config path `~/.codeium/windsurf/mcp_config.json`. Updated error messages to include `windsurf` in the known clients list.

**Regression test:** `test_known_clients_includes_windsurf`

---

## Bug 3: macOS-only Claude Desktop config path

**Severity: Medium**
**Status: Fixed**
**Files: `clients/clawdefender-cli/src/commands/mod.rs`**

`known_clients()` hardcoded the Claude Desktop config path to `~/Library/Application Support/Claude/claude_desktop_config.json`, which is macOS-only. On Linux, Claude Desktop uses `~/.config/Claude/claude_desktop_config.json`.

**Fix:** Added `#[cfg(target_os = "macos")]` and `#[cfg(target_os = "linux")]` conditional compilation for the Claude Desktop config path.

**Regression test:** `test_known_clients_includes_claude_on_macos` (macOS only)

---

## Bug 4: Wrap error message says "No mcpServers found" for non-Claude clients

**Severity: Low**
**Status: Fixed**
**Files: `clients/clawdefender-cli/src/commands/wrap.rs`, `unwrap.rs`**

When a Cursor or VS Code config file had no servers section, the error message said "No mcpServers found in ..." which is confusing because Cursor uses `"servers"` as the key.

**Fix:** Changed error message to "No MCP servers found in ..." which is client-agnostic.

---

## Bug 5: `McpClient` struct lacks `servers_key` field

**Severity: Medium**
**Status: Fixed**
**Files: `clients/clawdefender-cli/src/commands/mod.rs`**

The `McpClient` struct had no way to communicate which JSON key a client uses for its servers object. This made it impossible for downstream code to know whether to use `"mcpServers"` or `"servers"`.

**Fix:** Added `servers_key: &'static str` field to `McpClient`. During auto-detection, if the detected key differs from the default, it's updated on the returned client.

---

## Bug 6: Legacy `_clawai_original` key not tested

**Severity: Low**
**Status: Fixed (test added)**
**Files: `clients/clawdefender-cli/src/commands/unwrap.rs`**

The unwrap code handled the legacy `_clawai_original` key but had no test covering this path.

**Fix:** Added `test_unwrap_legacy_clawai_original` regression test.
