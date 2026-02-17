# MCP Server Compatibility Bugs

Found during Phase 6R server compatibility QA of `clawdefender-mcp-proxy`.

## Bug 1: Proxy Transparency - Deserialize/Reserialize Destroys Original Bytes (CRITICAL)

**Status:** FIXED

**Location:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs`

**Description:** Both client-to-server and server-to-client relay paths deserialized JSON-RPC
messages into Rust structs and then reserialized them with `serialize_message()` before
forwarding. This caused:

- Whitespace normalization (extra spaces removed, formatting changed)
- JSON key reordering (serde_json serializes in insertion order, not original order)
- Unicode escape sequence normalization (`\u65e5` becomes direct UTF-8 bytes)
- Floating-point representation changes

This made the proxy non-transparent. Some MCP servers and clients may validate message
checksums or depend on exact byte representations.

**Fix:** Introduced `RawJsonRpcMessage` type that pairs the parsed `JsonRpcMessage` with the
original raw bytes. The stream parser now has `next_raw_message()` which returns both. All
forwarding paths now use the original raw bytes instead of re-serializing. Only proxy-generated
responses (block errors) use `serialize_message()`.

**Regression tests:** Added 6 tests in `parser.rs`:
- `raw_message_preserves_exact_bytes`
- `raw_message_preserves_unicode_escapes`
- `raw_message_preserves_key_ordering`
- `raw_bytes_with_newline_appends_newline`
- `raw_message_notification_no_id`
- `raw_message_null_id_response`

## Bug 2: No Null ID Support in JsonRpcId

**Status:** FIXED

**Location:** `crates/clawdefender-mcp-proxy/src/jsonrpc/types.rs`

**Description:** `JsonRpcId` only supported `Number(i64)` and `String(String)` variants. Per
the JSON-RPC 2.0 specification, `id` can be `null` in error responses when the request ID
could not be determined (e.g., parse errors). Messages with `"id": null` would fail to
deserialize.

**Fix:** Added `Null` variant to `JsonRpcId` enum.

**Regression tests:** Added 2 tests in `types.rs`:
- `deserialize_response_with_null_id`
- `serialize_null_id_roundtrip`

## Bug 3: No JSON-RPC Batch Request Support (Known Limitation)

**Status:** DOCUMENTED (not fixed - by design)

**Location:** `crates/clawdefender-mcp-proxy/src/jsonrpc/types.rs`

**Description:** JSON-RPC 2.0 allows batch requests as JSON arrays. The proxy's
`JsonRpcMessage::deserialize` requires the message to be a JSON object. Batch requests
(arrays) are rejected as malformed.

**Impact:** Low. MCP protocol does not use batch requests in practice. The current MCP
specification (2024-11-05) defines single request/response pairs over stdio. If a client
sends a batch, the parser logs a warning and skips it.

**Mitigation:** The `StreamParser` gracefully handles this by logging a warning and
continuing to process subsequent messages. No crash occurs.

## Bug 4: Server stderr Not Logged via tracing

**Status:** DOCUMENTED (minor)

**Location:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs` line 178

**Description:** Child process stderr is set to `Stdio::inherit()`, which forwards
it to the proxy's stderr. This means server error output goes directly to the
proxy's stderr stream without being captured in structured tracing logs.

**Impact:** Low. Server errors appear in terminal output but are not captured in
structured audit logs. This is acceptable for the stdio transport where stderr is
the standard debug output channel.

## Bug 5: No Server Startup Timeout

**Status:** DOCUMENTED (minor)

**Location:** `crates/clawdefender-mcp-proxy/src/proxy/stdio.rs`

**Description:** When spawning the child MCP server, there is no explicit timeout
waiting for the server to become ready. If the server takes a long time to start
(or hangs during startup), the proxy waits indefinitely. The client may timeout
on the MCP side, but the proxy itself has no startup health check.

**Impact:** Medium. In practice, MCP servers start quickly. The client will
timeout on the initialize request if the server is too slow.

## Bug 6: Classifier Correctly Handles Unknown Methods

**Status:** VERIFIED (not a bug)

The classifier correctly routes unknown/vendor methods to `Classification::Log`,
which forwards them while recording in the audit trail. This is the correct
behavior for MCP compatibility - unknown methods should not be blocked.

**Regression tests:** Added 4 tests in `classifier/rules.rs`:
- `classify_vendor_method_logs`
- `classify_unicode_method_logs`
- `classify_method_with_dots_and_slashes`
- `classify_empty_method_logs`
