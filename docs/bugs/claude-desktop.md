# Claude Desktop Integration Bugs

## Bug 1: CRITICAL - `wrap` writes bare "clawdefender" instead of absolute path

**File:** `clients/clawdefender-cli/src/commands/wrap.rs:63`
**Severity:** Critical (blocks usage)
**Status:** Fixed

**Description:** The `wrap` command wrote `json!("clawdefender")` as the command in the
Claude Desktop config. Claude Desktop does NOT inherit the user's shell PATH (it launches
from launchd, not a shell), so the binary would not be found at runtime.

**Fix:** Added `resolve_clawdefender_path()` function that:
1. First tries `std::env::current_exe()` to get the path of the currently running binary
2. Falls back to `which clawdefender` to search PATH
3. Last resort: returns bare "clawdefender" (for testing environments)

The resolved absolute path (e.g. `/opt/homebrew/bin/clawdefender`) is written to the
config so Claude Desktop can find it regardless of PATH.

**Regression test:** Manual verification -- wrap a server and inspect the config to confirm
an absolute path is written.

---

## Bug 2: CRITICAL - Proxy tracing subscriber writes to stdout (poisons JSON-RPC stream)

**File:** `crates/clawdefender-mcp-proxy/src/main.rs:40-42`
**Severity:** Critical (breaks Claude Desktop)
**Status:** Fixed

**Description:** The `tracing_subscriber::fmt().init()` call in the proxy binary's
`main()` defaults to writing log output to stdout. When the proxy runs as a stdio
MCP proxy, ANY non-JSON-RPC output on stdout corrupts the message stream and causes
Claude Desktop to disconnect or show errors.

**Fix:** Added `.with_writer(std::io::stderr)` to the tracing subscriber so all log
output goes to stderr, keeping stdout clean for JSON-RPC messages only.

---

## Bug 3: CRITICAL - CLI tracing subscriber writes to stdout

**File:** `clients/clawdefender-cli/src/main.rs:243-245`
**Severity:** Critical (breaks Claude Desktop when using `clawdefender proxy`)
**Status:** Fixed

**Description:** Same issue as Bug 2 but in the CLI binary. When the wrapped config
invokes `clawdefender proxy -- <server>`, the CLI's tracing subscriber wrote to stdout,
poisoning the JSON-RPC stream.

**Fix:** Added `.with_writer(std::io::stderr)` to the CLI's tracing subscriber.

---

## Bug 4: MEDIUM - Proxy deserializes/reserializes messages instead of forwarding raw bytes

**File:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs` (channel-based relay)
**Severity:** Medium (subtle formatting changes)
**Status:** Fixed

**Description:** The channel-based `handle_client_message` function was using
`serialize_message(&msg)` to forward messages, which deserializes the JSON then
re-serializes it via serde. This can:
- Reorder JSON object keys
- Normalize whitespace
- Change numeric formatting (e.g. `1.0` -> `1`)

While valid JSON-RPC, some servers may be sensitive to exact byte representations.

**Fix:** Updated `handle_client_message` to accept `RawJsonRpcMessage` (which bundles
the parsed message with the original raw bytes). Forwarding now uses
`raw_msg.raw_bytes_with_newline()` to send the original bytes unchanged. The parsed
representation is still used for classification and policy evaluation.

---

## Bug 5: LOW - No JSON-RPC batch array handling

**File:** `crates/clawdefender-mcp-proxy/src/jsonrpc/parser.rs`
**Severity:** Low (MCP does not use batch requests in practice)
**Status:** Not fixed (deferred)

**Description:** The JSON-RPC parser only handles single JSON objects per line. If a
client sends a JSON-RPC batch array `[{...}, {...}]`, the parser would reject it as
malformed. The MCP specification does not use batch requests, but the JSON-RPC 2.0
spec technically allows them.

**Mitigation:** The parser logs a warning and skips malformed lines, so a batch would
be skipped rather than crashing the proxy. This is acceptable for now since no known
MCP clients send batch requests.

---

## Items Verified (No Bugs Found)

### Double-wrap prevention
The `is_wrapped()` function correctly checks for `_clawdefender_original` key. If a
server is already wrapped, `wrap` prints a message and returns successfully (idempotent).

### Unwrap of non-wrapped server
Returns a clear message: "This server is not wrapped by ClawDefender."

### Config backup
`backup_config()` creates a `.json.bak` file before any modification.

### Server not found error
Lists all available servers when the requested server name is not found.

### Config file handling
`read_config()` / `write_config()` correctly handle the Claude Desktop config path
at `~/Library/Application Support/Claude/claude_desktop_config.json`. Uses 2-space
indent formatting with trailing newline.

### Notification handling
MCP notifications (no `id` field) are correctly parsed as `JsonRpcNotification` and
classified as `Pass` or `Log`. The `request_id()` function returns `None` for
notifications, so no error response is generated.

### Non-string JSON-RPC IDs
The `JsonRpcId` enum handles both `Number(i64)` and `String(String)` variants via
`#[serde(untagged)]`.

### Large response handling
The parser enforces a 10 MB per-message limit and a 20 MB buffer limit, with proper
error handling that doesn't crash the proxy.

### Initialize sequence
The `initialize` method is classified as `Classification::Pass`, so it's forwarded
transparently without policy evaluation or logging overhead.

### Ping/keepalive
The `ping` method is classified as `Classification::Pass` -- not treated as a
security event.

### Proxy startup timing
The proxy spawns the child process and immediately starts reading from stdin. There
is no blocking initialization before the relay loops start, so the proxy is ready to
receive `initialize` immediately.

### Cancellation forwarding
Unknown methods (including `$/cancelRequest`) are classified as `Classification::Log`,
meaning they are logged and forwarded without blocking.

### Error responses
Server error responses are forwarded unchanged (via raw bytes in the server relay loop).
