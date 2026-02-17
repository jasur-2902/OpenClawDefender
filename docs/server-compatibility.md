# MCP Server Compatibility Notes

This document describes the proxy's compatibility characteristics with various MCP
servers and clients.

## Proxy Transparency

The ClawDefender MCP proxy is designed to be **transparent** to both clients and
servers. Messages that are forwarded (not blocked) are passed through as original
bytes without modification.

### What is preserved:
- JSON key ordering
- Whitespace and formatting
- Unicode escape sequences (e.g., `\u65e5` is NOT expanded to UTF-8)
- Numeric precision
- Trailing/leading whitespace within JSON strings

### What is NOT preserved:
- Blocked messages receive a proxy-generated JSON-RPC error response
- The proxy adds a newline delimiter to each forwarded message (per NDJSON protocol)

## JSON-RPC 2.0 Compliance

### Supported message types:
- **Requests**: Object with `id` + `method` fields
- **Responses**: Object with `id` field (no `method`)
- **Notifications**: Object with `method` field (no `id`)

### ID types supported:
- Numeric (`"id": 42`)
- String (`"id": "abc-123"`)
- Null (`"id": null`) - for error responses per JSON-RPC spec

### Known limitations:
- **Batch requests** (JSON arrays) are not supported. They are logged as malformed
  and skipped. This is acceptable because the MCP protocol does not use batch requests.
- Messages exceeding 10 MB are rejected.
- JSON nesting depth exceeding 128 levels is rejected.

## Server Lifecycle

### Startup:
- The proxy spawns the child server and immediately begins relaying messages.
- No explicit startup timeout or health check is performed.
- If the server fails to start, the proxy will detect the closed stdout pipe.

### Shutdown:
- When the client closes stdin (EOF), the proxy closes the child's stdin.
- The proxy waits up to 5 seconds for the child to exit gracefully.
- If the child does not exit within 5 seconds, it is killed with SIGKILL.

### Server crash:
- If the child process dies, the proxy detects the closed stdout pipe.
- The proxy logs the event and exits cleanly.
- Pending client requests do NOT receive an error response (they will timeout
  on the client side).

### Server stderr:
- Child process stderr is inherited by the proxy process.
- Server error output appears on the proxy's stderr.
- Server stderr is NOT parsed as JSON-RPC (correct behavior).

## Stream Handling

### Malformed messages:
- Non-JSON lines from the server stdout are logged and skipped.
- The proxy continues processing subsequent valid messages.
- A buggy server writing debug prints to stdout will not crash the proxy.

### Large messages:
- Messages up to 10 MB are supported.
- Messages exceeding 10 MB are rejected with a warning.
- The internal buffer is cleared if it exceeds 20 MB without a newline.

### Progress tokens:
- Progress notifications from the server are forwarded transparently.
- The proxy does not interpret or modify progress tokens.

## Error Fidelity

### Server errors forwarded:
- When the server returns a JSON-RPC error, the proxy forwards it with
  the exact error code, message, and data fields preserved (via raw byte forwarding).

### Policy block errors:
- Error code: `-32001` (custom, per JSON-RPC reserved range for application errors)
- Error message: Human-readable description of why the request was blocked
- Error data: Optional object with `rule` and `action` fields

## Classification Rules

| Method | Classification | Behavior |
|--------|---------------|----------|
| `initialize`, `initialized`, `ping` | Pass | Forward without logging |
| `notifications/*` | Pass | Forward without logging |
| `tools/list`, `resources/list`, `prompts/list` | Log | Forward and audit |
| `tools/call` | Review | Evaluate against policy |
| `resources/read` | Review | Evaluate against policy |
| `sampling/createMessage` | Review | Evaluate against policy |
| All responses | Pass | Forward without logging |
| Unknown methods | Log | Forward and audit |
| Vendor methods (e.g., `vendor.acme/custom`) | Log | Forward and audit |
