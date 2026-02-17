# Claw Compliant Certification Specification

**Version:** 0.5.0
**Status:** Draft

## Overview

The "Claw Compliant" certification program verifies that MCP servers work correctly
with ClawDefender, the firewall for AI agents. Certification is divided into three
progressive levels, each building on the previous one.

## Compliance Levels

### Level 1 — Transparent

The MCP server works correctly when placed behind a ClawDefender proxy. No code
changes are required; the server simply needs to handle the conditions that
ClawDefender introduces.

**Requirements:**

1. **Survives blocked tool calls.** When ClawDefender blocks a `tools/call` request
   and returns a JSON-RPC error with code `-32001`, the server must not crash. It
   must continue processing subsequent requests normally.

2. **Handles prompt delays.** When ClawDefender pauses a request to prompt the user
   (introducing up to 30 seconds of latency), the server must not time out or
   error. When the prompt is denied, the server must handle the resulting `-32001`
   error gracefully.

3. **Tolerates added latency.** ClawDefender adds logging and policy evaluation
   overhead. The server must continue to function when requests take longer than
   usual to complete.

4. **Handles JSON-RPC errors gracefully.** Any error response from ClawDefender
   (including `-32001 Blocked by policy`) must be handled without crashing or
   entering an inconsistent state.

5. **Continues after partial blocks.** In a session where some tool calls are
   blocked and others are allowed, the server must continue operating for the
   allowed calls.

### Level 2 — Cooperative

The MCP server actively integrates with ClawDefender using the SDK. This level
requires code changes but provides a better user experience.

**Requirements (in addition to Level 1):**

1. **Calls `checkIntent` before sensitive operations.** Before executing tool calls
   that perform file writes, shell execution, network access, or other sensitive
   operations, the server calls `clawdefender/checkIntent` to verify the action is
   permitted.

2. **Respects denials.** When `checkIntent` returns `{ "allowed": false }`, the
   server does NOT proceed with the operation. Instead, it returns a user-friendly
   error message explaining that the action was denied.

3. **Calls `reportAction` after execution.** After completing tool calls, the
   server calls `clawdefender/reportAction` to log what was done, enabling audit
   trails.

4. **Operates without ClawDefender.** When ClawDefender is unavailable (connection
   refused, not running), the server starts normally and operates without security
   checks. It must not crash or refuse to start.

### Level 3 — Proactive

The MCP server declares its security posture upfront and actively participates in
the ClawDefender security model.

**Requirements (in addition to Level 2):**

1. **Ships a `clawdefender.toml` manifest.** The server package includes a manifest
   file declaring its permissions, risk profile, and ClawDefender support level.

2. **Declares permissions.** The manifest lists all required and optional
   permissions with justifications.

3. **Calls `requestPermission` with justifications.** Before first use of a
   capability, the server calls `clawdefender/requestPermission` with a meaningful
   human-readable justification.

4. **Calls `getPolicy` on startup.** During initialization, the server calls
   `clawdefender/getPolicy` to learn the active policy and adapt its behavior.

5. **Graceful degradation.** When permissions are denied, the server continues
   operating with reduced functionality rather than failing entirely.

## Manifest Format (`clawdefender.toml`)

```toml
[server]
name = "my-server"
version = "1.0.0"
description = "What this server does"

[permissions]
required = [
    { action = "file_read", scope = "~/Projects/**", justification = "Core functionality" },
]
optional = [
    { action = "shell_execute", justification = "Git operations" },
]

[risk_profile]
max_risk = "medium"            # low | medium | high
declares_all_actions = true
supports_clawdefender = true
sdk_version = "0.5.0"
```

## Certification Process

1. Run `clawdefender certify -- <server-command>`.
2. The harness starts the target server as a child process over stdio.
3. Level 1 tests run adversarial scenarios against the server.
4. Level 2 tests instrument ClawDefender to observe SDK usage.
5. Level 3 tests check for manifest and proactive security calls.
6. A report is generated showing pass/fail for each test and the overall level.

## Report Ratings

- **PASS**: All tests in the level passed.
- **PARTIAL**: At least half the tests in the level passed.
- **FAIL**: More than half the tests in the level failed.

The overall compliance level is the highest level that received a PASS rating.

## Machine-Readable Output

Use `--json` to get a JSON report:

```json
{
  "server_name": "my-server",
  "timestamp": "2025-01-15T10:30:00Z",
  "tool_version": "0.5.0",
  "levels": {
    "level1": {
      "name": "Transparent",
      "tests": [...],
      "result": "PASS"
    },
    "level2": { ... },
    "level3": { ... }
  },
  "overall_level": 2
}
```
