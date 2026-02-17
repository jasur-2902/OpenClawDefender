# ClawDefender SDK Security Guide

This document describes the security model, hardening measures, and known
limitations of the ClawDefender MCP server and SDKs.

## Trust Model

ClawDefender implements a **cooperative security** model. MCP servers and AI
agents voluntarily declare their intents, request permission for sensitive
operations, and report actions for audit purposes. The daemon then enforces
policy and logs all activity.

**Trust boundaries:**

- The **daemon** is trusted — it runs with the user's privileges and enforces
  policy decisions.
- **MCP servers** are semi-trusted — they communicate through the MCP protocol
  and are subject to rate limiting, input validation, and authentication.
- **AI agents** are untrusted — their actions are mediated through MCP servers
  and subject to all security controls.

## Rate Limits and Abuse Prevention

The MCP server enforces per-caller rate limits to prevent abuse:

| Tool                | Limit           | Window   | Purpose                        |
|---------------------|-----------------|----------|--------------------------------|
| `requestPermission` | 10 calls        | 60 sec   | Prevent prompt flooding        |
| `checkIntent`       | 100 calls       | 60 sec   | Prevent intent-check abuse     |
| `reportAction`      | 1,000 calls     | 60 sec   | Prevent audit log pollution    |
| `reportAction`      | 10 KB max       | per call | Prevent oversized payloads     |

When a rate limit is exceeded, the server returns a JSON-RPC error with code
`-32000` (rate limited). For `requestPermission`, exceeding the limit causes
the server to be **permanently blocked for the session** to prevent prompt
fatigue attacks.

## HTTP Authentication

When the ClawDefender daemon starts with HTTP transport enabled, it generates
a random 256-bit token and writes it to:

```
~/.local/share/clawdefender/server-token
```

The file has `0600` permissions (owner read/write only).

All HTTP requests to the MCP server must include:

```
Authorization: Bearer <token>
```

SDKs automatically read this token file on startup. Stdio connections do not
require authentication (they are already scoped to the parent process).

Token validation uses constant-time comparison to prevent timing attacks.

## Input Validation

All string fields sent to the MCP server are validated:

- **Maximum length**: 4,096 characters per field
- **Null bytes**: Rejected (prevents injection attacks)
- **Unicode bidirectional overrides**: Rejected (prevents text reordering
  attacks using U+202A–U+202E, U+2066–U+2069)
- **Payload size**: `reportAction` payloads are limited to 10 KB

The Python and TypeScript SDKs perform the same validation client-side before
sending requests, providing defense in depth.

## Permission Scope Escalation Prevention

When `requestPermission` is called, the resource path must be **exact** — no
glob wildcards (`*`, `?`, `[`) are allowed. This ensures that a permission
grant for `/home/user/.ssh/config` cannot be escalated to match
`/home/user/.ssh/*`.

Session rules created from permission grants use the exact path as specified
in the request.

## Certification Sandbox Model

The `clawdefender certify` command runs MCP servers in a sandboxed environment
to verify compliance. During certification:

1. The server runs with a test policy that includes blocked resources
2. All MCP tool calls are captured and analyzed
3. The server must correctly handle denied permissions without crashing
4. Compliance level (Bronze/Silver/Gold) is determined by behavior

## Known Limitations

### Fail-Open When Daemon Is Killed

Both SDKs operate in **fail-open** mode by default: if the ClawDefender daemon
is unreachable, all `checkIntent` calls return `allowed: true` and all
`requestPermission` calls return `granted: true`.

This is a deliberate design choice — MCP servers should continue functioning
even if ClawDefender is temporarily unavailable. However, an attacker who can
kill the daemon process can bypass all policy enforcement.

**Mitigations:**

- The daemon monitors its own health and restarts automatically
- The fail-open behavior can be disabled by setting `fail_open: false` in SDK
  configuration (Python) or omitting the FailOpenConnection wrapper
- System-level process protection (e.g., macOS LaunchDaemon) prevents
  unauthorized process termination

### Self-Declared Identity

MCP servers identify themselves by name during the `initialize` handshake.
This name is self-declared and can be spoofed. For HTTP connections, the
authentication token provides caller verification. For stdio connections,
process identity (PID, executable path) provides some assurance but is not
cryptographically verified.

### macOS Case Sensitivity

On macOS HFS+ (case-insensitive filesystem), the paths `/etc/passwd` and
`/ETC/PASSWD` refer to the same file, but the policy matcher treats them as
different strings. This is a known limitation.

## Recommendations for MCP Server Authors

1. **Always call `checkIntent` before sensitive operations.** Even if you
   expect the action to be allowed, the check creates an audit trail.

2. **Use exact resource paths.** Avoid constructing paths from user input
   without sanitization. Use absolute paths where possible.

3. **Handle denied permissions gracefully.** When `requestPermission` returns
   `granted: false`, provide a helpful error message to the user rather than
   crashing or retrying.

4. **Report all actions.** Call `reportAction` after performing any operation,
   whether it succeeded or failed. This creates a complete audit trail.

5. **Do not log tokens.** The authentication token should never appear in logs,
   error messages, or debug output. The SDKs are designed to handle token
   management transparently.

6. **Set `fail_open: false` for high-security environments.** If your MCP
   server handles sensitive operations, consider disabling fail-open mode to
   ensure all actions are policy-checked.

7. **Keep the SDK updated.** Security improvements are released regularly.
   Pin to a minor version range (e.g., `^0.5.0`) to receive patches.
