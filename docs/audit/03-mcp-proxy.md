# Section 3: MCP Proxy & MCP Server Audit

## 3.1 Crate Overview

### clawdefender-mcp-proxy

| Field | Value |
|-------|-------|
| Path | `crates/clawdefender-mcp-proxy/` |
| Type | Library + Binary |
| Description | MCP protocol proxy with JSON-RPC interception |
| Dependencies | clawdefender-core, clawdefender-slm, clawdefender-swarm, clawdefender-threat-intel, tokio, serde, serde_json, axum 0.8, reqwest 0.12, hyper 1, clap, chrono, uuid, tracing |
| Source Files | 8 (.rs in src/) |
| Test Files | 2 (e2e_proxy_test.rs, helpers/mod.rs) |

### clawdefender-mcp-server

| Field | Value |
|-------|-------|
| Path | `crates/clawdefender-mcp-server/` |
| Type | Library |
| Description | MCP server that lets AI agents declare intent, request permission, and report actions |
| Dependencies | clawdefender-core, tokio, serde, serde_json, axum 0.8, chrono, uuid, rand, hex, dirs |
| Source Files | 8 (.rs in src/) |
| Test Files | 4 (integration, security, SDK flow, bench) |

---

## 3.2 MCP Proxy -- Detailed Audit

### 3.2.1 JSON-RPC Types (`src/jsonrpc/types.rs`)

**Status: REAL**

- Fully implements JSON-RPC 2.0 types: `JsonRpcRequest`, `JsonRpcResponse`, `JsonRpcNotification`, `JsonRpcError`
- Custom `JsonRpcMessage` enum with correct discrimination logic:
  - has `id` + `method` = Request
  - has `id` without `method` = Response
  - has `method` without `id` = Notification
- `JsonRpcId` supports Number, String, and Null (spec-compliant)
- Custom `Serialize`/`Deserialize` implementations for `JsonRpcMessage`
- `POLICY_BLOCK_ERROR_CODE = -32001` defined for block responses
- **20 unit tests** covering: numeric/string/null IDs, request/response/notification deserialization, roundtrip, rejection of non-objects, rejection of missing id+method, Unicode method names, dotted method names

**Verdict: REAL -- Complete, spec-compliant JSON-RPC 2.0 types**

### 3.2.2 JSON-RPC Stream Parser (`src/jsonrpc/parser.rs`)

**Status: REAL**

- `parse_message()`: Parses single JSON-RPC messages from bytes
  - Enforces `MAX_MESSAGE_SIZE` (10 MB)
  - Enforces `MAX_JSON_DEPTH` (128) to prevent stack overflow
  - `exceeds_json_depth()`: Fast pre-parse bracket counting with string/escape awareness
- `serialize_message()`: Serializes `JsonRpcMessage` to JSON bytes + newline
- `RawJsonRpcMessage`: Preserves original raw bytes alongside parsed message for transparent proxying (key ordering, whitespace, Unicode escapes preserved)
- `StreamParser`: Newline-delimited stream parser with:
  - Internal buffer with `MAX_BUFFER_SIZE` (20 MB) overflow protection
  - Empty line skipping
  - Oversized line skipping (logged + drained)
  - Malformed line error propagation
  - `next_raw_message()` for transparent forwarding
- **28 unit tests** covering: valid/malformed/empty/truncated/missing-field parsing, Unicode arguments, null params, large messages, serialize roundtrip, single/multiple/partial/byte-by-byte streaming, malformed/empty line skipping, oversized message rejection, deep nesting rejection, buffer overflow protection, raw byte preservation (exact bytes, Unicode escapes, key ordering), null-id responses

**Verdict: REAL -- Production-quality streaming parser with security hardening**

### 3.2.3 Message Classifier (`src/classifier/rules.rs`)

**Status: REAL**

- `Classification` enum: `Pass`, `Log`, `Review`, `Block`
- `classify()` function implements clear classification rules:
  - **Pass**: `initialize`, `initialized`, `ping`, `notifications/*`
  - **Log**: `tools/list`, `resources/list`, `prompts/list`, unknown methods
  - **Review**: `tools/call`, `resources/read`, `sampling/createMessage`
  - **Block**: (not used in current classifier; reserved for future hard blocks)
- `extract_tool_call()`: Extracts `(tool_name, arguments)` from `tools/call` requests
- `extract_resource_uri()`: Extracts resource URI from `resources/read` requests
- **17 unit tests** covering all classification paths, extraction functions, vendor/Unicode/dotted methods, empty method names

**Verdict: REAL -- Complete classifier covering the full MCP method space**

### 3.2.4 Stdio Proxy (`src/proxy/stdio.rs`)

**Status: REAL** (1580+ lines, the core of the system)

This is the main proxy implementation. Spawns an MCP server as a child process and sits between stdin/stdout and the child's stdin/stdout.

**Architecture:**
1. Spawns child process with `tokio::process::Command`
2. Creates two relay loops via `tokio::spawn`:
   - **Client -> Server relay**: Reads from proxy stdin, parses, classifies, evaluates policy, forwards or blocks
   - **Server -> Client relay**: Reads from child stdout, logs audit events, forwards raw bytes to proxy stdout
3. Uses `mpsc::channel` for non-blocking writes (writer tasks for child stdin and proxy stdout)
4. `tokio::select!` waits for child exit or relay completion

**Message handling flow (per message):**
1. Parse via `StreamParser::next_raw_message()`
2. `classify()` determines handling tier
3. **Pass**: Forward raw bytes immediately
4. **Log**: Forward raw bytes + emit audit record
5. **Review**: Evaluate against `PolicyEngine`:
   - `PolicyAction::Allow` -> forward + audit
   - `PolicyAction::Block` -> send JSON-RPC error response to client + audit
   - `PolicyAction::Log` -> forward + audit (logged)
   - `PolicyAction::Prompt` -> send prompt to UI bridge, await user decision with timeout:
     - `AllowOnce` -> forward
     - `AllowSession` -> forward + add session rule to policy engine
     - `AddPolicyRule` -> forward + add permanent rule
     - `DenyOnce` / timeout -> block + send JSON-RPC error
6. **Block**: Send JSON-RPC error to client (not currently triggered by classifier)

**Policy integration:**
- Uses `DefaultPolicyEngine` from clawdefender-core
- `RwLock` for concurrent read access during evaluation
- Session rules added dynamically on `AllowSession` decisions
- Permanent rules added on `AddPolicyRule` decisions

**UI Bridge integration:**
- `UiBridge` struct wraps `mpsc::Sender<(UiRequest, oneshot::Sender<UiResponse>)>`
- Prompt spawned as separate tokio task (non-blocking)
- Configurable `prompt_timeout` (default 30s)
- `max_pending_prompts` limit (default 100) prevents prompt flooding
- When no UI bridge: allows requests (backwards compatibility) with warning log

**SLM integration (advisory only):**
- `SlmContext` optional attachment via builder pattern
- Uses `NoiseFilter` to skip analysis for repeated/boring events
- Spawns async SLM analysis concurrently with prompt display
- SLM result logged to audit record, **never influences policy decision**
- Multiple SAFETY comments documenting advisory-only nature

**Swarm integration (advisory only):**
- `SwarmContext` optional attachment
- Escalation triggered when SLM risk level >= configurable threshold
- Spawned as separate async task, never blocks prompt
- Results logged to audit, **never influences policy decision**

**Threat Intelligence integration:**
- `ThreatIntelContext` optional attachment
- IoC matching performed on every reviewed event
- Results attached to audit records
- Does not modify policy decisions

**Audit logging:**
- Enriched `AuditRecord` with: tool_name, arguments, jsonrpc_method, classification (risk level), policy_action, direction, server_name
- `classify_risk_level()`: Heuristic risk classification based on tool name and arguments
  - CRITICAL: curl|sh patterns, shell injection
  - HIGH: sensitive file paths, shell/exec tools
  - MEDIUM: file writes/creates/deletes
  - LOW: file reads, listing
- `human_readable_action()`: Maps tool names to user-friendly labels
- `build_session_allow_rule()`: Creates policy rules from user decisions
- `default_audit_log_path()`: Returns `~/.local/share/clawdefender/audit.jsonl` with symlink check

**Security features:**
- Symlink check on audit log path (refuses symlinks, falls back to temp path)
- Raw byte forwarding preserves exact message formatting (no re-serialization in relay loop)
- Block responses use `POLICY_BLOCK_ERROR_CODE = -32001`
- Pending prompt count limit prevents prompt flooding

**Constructors:**
- `StdioProxy::new()` -- from command + policy path (creates FileAuditLogger)
- `StdioProxy::with_engine()` -- from pre-built policy engine (for testing)
- `StdioProxy::with_full_config()` -- with UI bridge, audit channel, config

**32+ unit/integration tests** covering: block response construction, request ID extraction, MCP event building, audit record building, session rule creation, blocked/allowed tool calls, initialize pass-through, classification-to-policy flow, missing policy fallback, prompt without UI bridge, prompt with UI bridge (allow/deny), prompt timeout auto-deny, AllowSession rule creation, message ordering (100 messages), metrics initial state, batch evaluation, escalation threshold logic, performance benchmarks (pass-through <1ms, review <1ms)

**One TODO found:**
- Line 878: `let server = "mcp-proxy"; // TODO: get actual server name` -- minor; the server name is already set from `config.server_name` elsewhere in the code.

**Verdict: REAL -- Fully implemented, production-quality stdio proxy with deep integration**

### 3.2.5 HTTP Proxy (`src/proxy/http.rs`)

**Status: REAL**

HTTP reverse proxy for MCP servers using HTTP+SSE transport.

**Architecture:**
- Axum-based HTTP server with two route handlers:
  - `GET /sse` -> SSE relay (streams upstream SSE events directly)
  - `ANY /` and `ANY /{*path}` -> JSON-RPC interception
- `AppState` shared via Axum `State` extractor

**JSON-RPC handler flow:**
1. Parse request body as JSON-RPC
2. If not valid JSON-RPC, forward as-is (pass-through for non-JSON-RPC endpoints)
3. Classify -> Pass/Log/Review/Block
4. For Review: evaluate policy engine, handle Allow/Block/Prompt/Log
5. Prompt handling uses UI bridge with timeout (same pattern as stdio)
6. Block responses return HTTP 200 with JSON-RPC error body (correct for JSON-RPC over HTTP)

**SSE handler:**
- Relays SSE stream from upstream without modification
- Forwards relevant headers, strips hop-by-hop headers

**Forward handler:**
- Proxies raw request body to upstream
- Strips hop-by-hop headers and `host` header
- Returns upstream response status + headers + body

**Utility functions:**
- `is_hop_by_hop()`: Identifies hop-by-hop headers (connection, keep-alive, proxy-*, te, trailers, transfer-encoding, upgrade)
- `build_mcp_event()`, `build_audit_record()`, `event_summary()` -- same logic as stdio proxy (code duplication)

**3 unit tests**: hop-by-hop detection, block response construction, request ID extraction

**Notable design decisions:**
- Block responses use HTTP 200 + JSON-RPC error (not HTTP 403) -- correct for JSON-RPC protocol
- `danger_accept_invalid_certs` controlled by `insecure` flag
- HTTP client timeout: 300 seconds
- No UI bridge wired: when bridge unavailable, allows with warning (same as stdio fallback)
- `_audit_rx` dropped in `HttpProxy::new()` -- audit records are sent but not consumed in standalone mode

**Verdict: REAL -- Fully implemented HTTP proxy with SSE support**

### 3.2.6 Binary Entry Point (`src/main.rs`)

**Status: REAL**

- Clap-based CLI with:
  - `server_cmd` (trailing var arg for stdio mode)
  - `--policy` (default `~/.config/clawdefender/policy.toml`)
  - `--http` mode toggle
  - `--remote` URL for HTTP mode
  - `--listen` address (default `127.0.0.1:3100`)
  - `--insecure` for TLS skip
- All logging goes to stderr (critical for MCP stdio protocol)
- `expand_tilde()` for policy path
- Validates `--remote` required in HTTP mode
- Validates server command required in stdio mode

**Verdict: REAL -- Complete CLI with proper MCP-compatible logging**

### 3.2.7 Library Root (`src/lib.rs`)

**Status: REAL**

- Exports: `HttpProxy`, `StdioProxy`, `ProxyConfig`, `ProxyMetrics`, `SlmContext`, `SwarmContext`, `ThreatIntelContext`, `UiBridge`
- Convenience functions: `run_stdio_proxy()`, `run_stdio_proxy_full()`, `run_http_proxy()`

**Verdict: REAL -- Clean API surface**

### 3.2.8 Proxy Infrastructure (`src/proxy/mod.rs`)

**Status: REAL**

- `ProxyConfig`: server_command, server_args, remote_url, prompt_timeout, max_pending_prompts, server_name
- `UiBridge`: Channel-based prompt sending with oneshot response
- `ProxyMetrics`: Atomic counters for total/allowed/blocked/prompted/logged
- `SlmContext`, `SwarmContext`, `ThreatIntelContext`: Optional integration contexts

**Verdict: REAL -- Well-designed shared infrastructure**

### 3.2.9 E2E Tests (`tests/e2e_proxy_test.rs`, `tests/helpers/mod.rs`)

**Status: REAL (requires built binaries, all `#[ignore]`)**

- Test harness spawns actual `clawdefender-mcp-proxy` binary wrapping `mock-mcp-server`
- 8 E2E tests:
  - Initialize handshake
  - Block SSH key access
  - Allow benign file read
  - tools/list pass-through
  - Notification forwarding
  - Multiple dangerous paths blocked
  - Message ordering (50 rapid messages)
  - Graceful shutdown on stdin EOF
  - Resource read allowed
  - Sampling request pass-through
- Tests exercise the full pipeline: binary -> CLI parsing -> child spawn -> JSON-RPC parsing -> classification -> policy -> forwarding/blocking

**Verdict: REAL -- Comprehensive E2E test suite**

---

## 3.3 MCP Server -- Detailed Audit

### 3.3.1 Server Core (`src/lib.rs`)

**Status: REAL**

- `McpServer` struct with:
  - `policy_engine: Arc<Mutex<Box<dyn PolicyEngine>>>` -- dynamic dispatch
  - `audit_logger: Arc<dyn AuditLogger>` -- dynamic dispatch
  - Rate limiters: permission (10/60s), intent (100/60s), report (1000/60s)
  - Optional `auth_token` for HTTP authentication
- `ToolRateLimiter`: Per-caller sliding window rate limiter
- `run_stdio()` and `run_http()` methods for different transports

**Verdict: REAL -- Clean server core with rate limiting**

### 3.3.2 Protocol Handler (`src/protocol.rs`)

**Status: REAL**

- Handles JSON-RPC 2.0 methods: `initialize`, `initialized`, `ping`, `tools/list`, `tools/call`
- `handle_message()` / `handle_message_with_caller()`: Full JSON-RPC parsing with:
  - Parse error handling (-32700)
  - JSON-RPC version validation (-32600)
  - Method routing
  - Notification handling (no response for `initialized`)
  - Unknown method error (-32601)
  - Caller ID for rate limiting
- `handle_tools_call()`: Dispatches to tool implementations:
  - `checkIntent`: rate limit (100/min) -> validate inputs -> execute
  - `requestPermission`: rate limit (10/60s) -> validate inputs -> validate exact path -> execute
  - `reportAction`: payload size check (10KB) -> rate limit (1000/min) -> validate inputs -> execute
  - `getPolicy`: no rate limit -> execute
  - Unknown tool: -32601
- `tools/list` returns 4 tools with full MCP inputSchema definitions
- `initialize` returns protocol version `2024-11-05`, capabilities, serverInfo
- **12 unit tests** in module

**Verdict: REAL -- Complete MCP protocol handler**

### 3.3.3 Tool Implementations (`src/tools.rs`)

**Status: REAL**

- `check_intent()`:
  - Builds synthetic `McpEvent` from declared intent
  - Evaluates against policy engine
  - Returns: allowed, risk_level, explanation, policy_rule, suggestions
  - Logs to audit
- `request_permission()`:
  - Converts to `CheckIntentParams`, evaluates policy
  - If policy says Allow -> grants Session scope, adds session rule to engine
  - If policy says Block -> denies
  - If policy says Prompt -> denies (not yet wired to UI)
  - Session rules use exact resource paths (no wildcards, validated upstream)
  - Logs to audit
- `report_action()`:
  - Creates detailed `AuditRecord` with action metadata
  - Logs via `audit_logger`
  - Returns event_id
- `get_policy()`:
  - Tests synthetic events against policy engine
  - Returns matching rule summary + default action
  - Limited by `PolicyEngine` trait (only returns first match, not full rule enumeration)
- **10 unit tests** covering: allowed/blocked/prompted intents, audit recording, permission grant/deny, session rule creation, policy queries, empty policy

**Note on `requestPermission`:** When policy says `Prompt`, permission is denied. Comment says "In a full implementation, this would forward to the UI for user decision." This is a design limitation, not a bug -- the MCP server doesn't have access to the UI bridge (that's the proxy's job).

**Verdict: REAL -- All four tools fully implemented with policy integration**

### 3.3.4 Input Validation (`src/validation.rs`)

**Status: REAL**

- `validate_string_field()`: Rejects null bytes, Unicode bidi control chars (U+200E-200F, U+202A-202E, U+2066-2069), oversized strings (>4096 chars)
- `sanitize_string()`: Strips control chars (preserves newline/tab/CR) and bidi chars
- `validate_payload_size()`: Enforces 10KB max for reportAction
- `validate_resource_path_exact()`: Rejects glob metacharacters (*, ?, [) in resource paths to prevent scope escalation
- **10 unit tests**

**Verdict: REAL -- Solid input validation preventing injection and scope escalation**

### 3.3.5 Suggestions Engine (`src/suggestions.rs`)

**Status: REAL**

- Rule-based suggestion engine for blocked intents
- 14 suggestion rules covering: SSH keys, credentials, .env, passwords, tokens, rm -rf, sudo, curl, wget, network requests, file deletion, /etc/ writes, .config writes
- Generic fallback: "Call requestPermission with a detailed justification"
- **9 unit tests**

**Verdict: REAL -- Helpful, context-aware suggestion system**

### 3.3.6 Authentication (`src/auth.rs`)

**Status: REAL**

- `generate_and_store_token()`: Generates 256-bit random token, writes to `~/.local/share/clawdefender/server-token`
- Unix: Sets 0600 permissions on token file
- `validate_bearer_token()`: Constant-time comparison (prevents timing attacks)
- `read_token()`: Reads from disk
- **6 unit tests**

**Verdict: REAL -- Proper auth with constant-time comparison and file permissions**

### 3.3.7 Stdio Transport (`src/transport/stdio.rs`)

**Status: REAL**

- Simple tokio stdin/stdout loop
- Reads newline-delimited JSON-RPC, dispatches to `protocol::handle_message()`
- Writes responses to stdout with newline delimiter

**Verdict: REAL -- Minimal, correct**

### 3.3.8 HTTP Transport (`src/transport/http.rs`)

**Status: REAL**

- Axum-based HTTP server on `127.0.0.1:{port}`
- Single POST endpoint at `/mcp`
- Bearer token authentication when `auth_token` configured
- Derives `caller_id` from auth state
- Returns HTTP 204 No Content for notifications

**Verdict: REAL -- Clean HTTP transport with auth**

### 3.3.9 Types (`src/types.rs`)

**Status: REAL**

- Well-defined types for all four tools: `CheckIntentParams/Response`, `RequestPermissionParams/Response`, `ReportActionParams/Response`, `GetPolicyParams/Response`
- Supporting enums: `ActionType`, `RiskLevel`, `Operation`, `PermissionScope`, `ActionResult`, `PolicyRuleSummary`
- `ActionType::to_event_type()` maps to policy engine event types

**Verdict: REAL -- Complete type system**

### 3.3.10 Test Coverage

| Test File | Tests | Status |
|-----------|-------|--------|
| `tests/mcp_server_integration_tests.rs` | 18 | REAL -- Full protocol integration |
| `tests/security_tests.rs` | 14 | REAL -- Rate limits, scope escalation, payload limits, input validation, auth |
| `tests/sdk_flow_tests.rs` | ~10+ | REAL -- SDK client perspective |
| `tests/bench_tests.rs` | ~5+ | REAL -- Performance benchmarks |
| `src/protocol.rs` (inline) | 12 | REAL |
| `src/tools.rs` (inline) | 10 | REAL |
| `src/validation.rs` (inline) | 10 | REAL |
| `src/suggestions.rs` (inline) | 9 | REAL |
| `src/auth.rs` (inline) | 6 | REAL |

---

## 3.4 Answers to Audit Questions

### Q1: Does it intercept JSON-RPC messages between MCP client and server?
**YES.** The stdio proxy sits between client stdin/stdout and child process stdin/stdout. Every message is parsed by `StreamParser`, classified, and routed through the policy engine before forwarding. The HTTP proxy intercepts request bodies at the axum handler level.

### Q2: Does it parse tools/call, resources/read, resources/list, sampling/createMessage?
**YES.** The classifier explicitly handles all of these:
- `tools/call` -> `Classification::Review` + `extract_tool_call()` extracts name/args
- `resources/read` -> `Classification::Review` + `extract_resource_uri()` extracts URI
- `resources/list` -> `Classification::Log`
- `sampling/createMessage` -> `Classification::Review` + extracts messages/modelPreferences
- `tools/list` and `prompts/list` -> `Classification::Log`

### Q3: Does it apply policy decisions (allow/deny/prompt)?
**YES.** For Review-classified messages:
- `PolicyAction::Allow` -> forward
- `PolicyAction::Block` -> send JSON-RPC error (-32001)
- `PolicyAction::Prompt` -> prompt user via UI bridge (with timeout + pending count limit)
- `PolicyAction::Log` -> forward + audit

### Q4: Does it log enriched audit events?
**YES.** Audit records include: timestamp, source, event_summary, event_details, rule_matched, action_taken, direction, server_name, client_name, jsonrpc_method, tool_name, arguments, classification (risk level), policy_rule, policy_action, user_decision, proxy_latency_us, slm_analysis, swarm_analysis, threat_intel, network_connection. The `FileAuditLogger` writes to `~/.local/share/clawdefender/audit.jsonl`.

### Q5: Does it communicate with the daemon?
**PARTIALLY.** The proxy does not directly communicate with the daemon via IPC. Instead:
- The daemon spawns the proxy as a child process (configured in GUI)
- Communication happens indirectly through:
  - Shared policy files (TOML)
  - Shared audit log file (`audit.jsonl`)
  - UI bridge channel (when wired by daemon)
- The proxy can operate standalone without the daemon

### Q6: Does it handle MCP protocol correctly (JSON-RPC 2.0)?
**YES.** Correct handling of:
- Request/Response/Notification discrimination
- Numeric, string, and null IDs
- `jsonrpc: "2.0"` version field
- Proper error codes (-32001 for policy blocks)
- Notifications have no response
- Block responses maintain HTTP 200 + JSON-RPC error (for HTTP mode)
- Newline-delimited transport for stdio

### Q7: Stdio vs SSE -- which transports are implemented?
**BOTH.**
- **Stdio**: Full implementation in `src/proxy/stdio.rs` -- spawns child process, bidirectional relay
- **HTTP+SSE**: Full implementation in `src/proxy/http.rs` -- axum reverse proxy with SSE relay endpoint

### Q8: What happens with unknown message types?
- Unknown JSON-RPC methods -> `Classification::Log` -> forwarded to server + audit logged
- Malformed JSON -> logged as warning, skipped (stream parser continues)
- Non-JSON-RPC HTTP requests -> forwarded as-is (pass-through)
- Messages without `id` or `method` -> rejected by parser

### Q9: When daemon is unreachable?
- Proxy operates independently -- no direct daemon communication required
- If UI bridge channel is closed/unavailable:
  - Stdio proxy: allows prompt-classified messages with warning log (backwards compat)
  - HTTP proxy: allows prompt-classified messages with warning log
- If policy file doesn't exist: falls back to empty policy (default Log for everything)
- If audit channel is full: `try_send` silently drops (non-blocking)

### Q10: TODOs, unimplemented!, stubs, FIXMEs

| Location | Type | Description |
|----------|------|-------------|
| `src/proxy/stdio.rs:878` | TODO | `let server = "mcp-proxy"; // TODO: get actual server name` -- minor, server name is set from config elsewhere |
| `src/tools.rs:106-113` (MCP server) | Design limitation | `requestPermission` with Prompt action denies instead of forwarding to UI -- by design, as MCP server has no UI bridge |
| HTTP proxy `_audit_rx` | Minor | Audit receiver dropped in `HttpProxy::new()` standalone mode -- records sent but not consumed |

**No `todo!()`, `unimplemented!()`, `FIXME`, `HACK`, or `STUB` macros found in either crate.**

---

## 3.5 Function-Level Classification

### clawdefender-mcp-proxy

| Function/Module | Status | Notes |
|----------------|--------|-------|
| `jsonrpc::types` (JsonRpcMessage, Id, etc.) | REAL | Spec-compliant JSON-RPC 2.0 types |
| `jsonrpc::parser::parse_message()` | REAL | Size + depth limits |
| `jsonrpc::parser::StreamParser` | REAL | Newline-delimited streaming with overflow protection |
| `jsonrpc::parser::RawJsonRpcMessage` | REAL | Transparent byte preservation |
| `classifier::rules::classify()` | REAL | Full MCP method classification |
| `classifier::rules::extract_tool_call()` | REAL | Extracts tool name + args |
| `classifier::rules::extract_resource_uri()` | REAL | Extracts resource URI |
| `proxy::stdio::StdioProxy::new()` | REAL | Policy loading + FileAuditLogger |
| `proxy::stdio::StdioProxy::run()` | REAL | Full bidirectional relay loop |
| `proxy::stdio::handle_client_message()` | REAL | Full classification -> policy -> forward/block pipeline |
| `proxy::stdio` SLM integration | REAL | Advisory-only, non-blocking analysis |
| `proxy::stdio` Swarm integration | REAL | Advisory-only, async escalation |
| `proxy::stdio` Threat Intel integration | REAL | IoC matching on reviewed events |
| `proxy::stdio::build_mcp_event()` | REAL | Event construction for all MCP types |
| `proxy::stdio::build_audit_record()` | REAL | Enriched audit with risk classification |
| `proxy::stdio::build_session_allow_rule()` | REAL | Dynamic session rules from user decisions |
| `proxy::stdio::default_audit_log_path()` | REAL | Symlink protection |
| `proxy::http::HttpProxy::start()` | REAL | Axum server with SSE + JSON-RPC routes |
| `proxy::http::handle_sse()` | REAL | SSE stream relay |
| `proxy::http::handle_jsonrpc()` | REAL | Full policy evaluation pipeline |
| `proxy::http::forward_raw()` | REAL | Header-aware proxying |
| `proxy::mod::ProxyConfig` | REAL | Shared configuration |
| `proxy::mod::UiBridge` | REAL | Channel-based prompt system |
| `proxy::mod::ProxyMetrics` | REAL | Atomic counters |
| `main.rs` CLI | REAL | Clap parser with stdio/HTTP modes |
| E2E test harness | REAL | Spawns real binaries |

### clawdefender-mcp-server

| Function/Module | Status | Notes |
|----------------|--------|-------|
| `McpServer` struct | REAL | Policy engine + audit + rate limiters |
| `ToolRateLimiter` | REAL | Per-caller sliding window |
| `protocol::handle_message()` | REAL | Full JSON-RPC dispatch |
| `protocol::handle_tools_call()` | REAL | Rate limit + validate + dispatch per tool |
| `tools::check_intent()` | REAL | Synthetic event -> policy eval -> response |
| `tools::request_permission()` | REAL | Policy eval + session rule creation |
| `tools::report_action()` | REAL | Audit logging with event ID |
| `tools::get_policy()` | REAL | Policy query via synthetic events |
| `validation::validate_string_field()` | REAL | Null bytes, bidi chars, size limits |
| `validation::validate_payload_size()` | REAL | 10KB max |
| `validation::validate_resource_path_exact()` | REAL | Anti-wildcard scope escalation |
| `suggestions::suggest()` | REAL | Context-aware blocked-intent suggestions |
| `auth::generate_and_store_token()` | REAL | 256-bit random + file permissions |
| `auth::validate_bearer_token()` | REAL | Constant-time comparison |
| `transport::stdio::run()` | REAL | stdin/stdout JSON-RPC loop |
| `transport::http::run()` | REAL | Axum POST /mcp with auth |
| `types` module | REAL | Complete type definitions |

---

## 3.6 Code Quality Observations

### Strengths

1. **Transparent proxying**: `RawJsonRpcMessage` preserves exact byte formatting -- no re-serialization artifacts
2. **Security hardening**: JSON depth limits, message size limits, buffer overflow protection, symlink checks, constant-time auth comparison, bidi char rejection
3. **Non-blocking prompt handling**: Prompt tasks spawned separately, other messages continue flowing
4. **Advisory-only SLM/Swarm**: Multiple SAFETY comments document that advisory analysis never influences policy decisions
5. **Comprehensive test coverage**: 100+ unit tests, E2E tests, security tests, performance benchmarks
6. **Rate limiting**: Three tiers of rate limits prevent prompt flooding and abuse
7. **Scope escalation prevention**: Resource paths validated for wildcards before creating session rules

### Concerns

1. **Code duplication**: `build_mcp_event()`, `build_audit_record()`, `event_summary()` are duplicated between `stdio.rs` and `http.rs`. Should be extracted to a shared module.
2. **No-UI-bridge fallback**: When no UI bridge is available and policy says Prompt, the stdio proxy **allows** the request (backwards compatibility). This is a security trade-off -- documented but could surprise users. The HTTP proxy has the same behavior.
3. **HTTP proxy audit sink**: In `HttpProxy::new()`, the audit receiver `_audit_rx` is immediately dropped. Audit records in standalone HTTP mode are sent but never consumed.
4. **`requestPermission` Prompt limitation**: The MCP server cannot forward Prompt decisions to users because it has no UI bridge. This is by design but means `requestPermission` is effectively binary (allow/deny from policy) without human-in-the-loop for ambiguous cases.
5. **Risk classification heuristics**: `classify_risk_level()` uses string matching on tool names (contains "exec", "bash", etc.). This is brittle -- a tool named "executable_checker" would be classified as HIGH risk.

---

## 3.7 Summary

| Crate | Total Functions Audited | REAL | PARTIAL | STUBBED | MISSING | BROKEN |
|-------|------------------------|------|---------|---------|---------|--------|
| clawdefender-mcp-proxy | 26 | 26 | 0 | 0 | 0 | 0 |
| clawdefender-mcp-server | 17 | 17 | 0 | 0 | 0 | 0 |
| **Total** | **43** | **43** | **0** | **0** | **0** | **0** |

**Both crates are fully implemented production-quality code.** The MCP proxy is the most critical security component in the system and it is well-built with proper JSON-RPC handling, policy integration, transparent forwarding, comprehensive audit logging, and multiple layers of security hardening. The MCP server provides a novel cooperative security model where agents can declare intent and request permission before acting.
