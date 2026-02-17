# MCP Protocol Reference

This document describes how ClawDefender interacts with the Model Context Protocol (MCP) and serves as a reference for developers extending ClawDefender or writing custom policies.

## How `clawdefender wrap` works

When you run `clawdefender wrap <server-name>`, ClawDefender modifies the MCP client configuration so that instead of launching the MCP server directly, the client launches ClawDefender, which in turn launches the real server.

**Before wrapping:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

**After wrapping:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "clawdefender",
      "args": ["proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

ClawDefender spawns the real server as a child process, connects to its stdin/stdout, and sits in the middle of all JSON-RPC communication.

For remote (HTTP/SSE) MCP servers, ClawDefender acts as a reverse proxy, forwarding requests after policy evaluation.

### Internals of `clawdefender wrap`

1. **Config detection:** ClawDefender auto-detects the MCP client by searching known config paths (Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`, Cursor: `~/.cursor/mcp.json`).
2. **Server lookup:** Finds the named server entry in `mcpServers`.
3. **Command rewriting:** Replaces the `command` with `clawdefender` and prepends `proxy --` before the original command and args.
4. **Backup:** Creates a `.bak` backup of the original config before modifying.
5. **Validation:** Parses the rewritten config to ensure it is valid JSON before writing.

`clawdefender unwrap <server-name>` reverses this process, restoring the original command.

## Intercepted JSON-RPC methods

ClawDefender intercepts and evaluates the following MCP methods:

| Method | Direction | What ClawDefender does |
|---|---|---|
| `tools/call` | Client -> Server | **Primary enforcement point.** Evaluates tool name and arguments against policy rules. May allow, deny, or prompt. |
| `tools/list` | Server -> Client | Logged for audit. ClawDefender records the declared tool set for a server, used later for correlation. |
| `resources/read` | Client -> Server | Evaluates the resource URI against policy rules. Can restrict which resources an agent accesses. |
| `resources/list` | Server -> Client | Logged for audit. Records available resources. |
| `sampling/createMessage` | Server -> Client | Evaluates sampling requests. Can block or modify prompts that match injection patterns. |
| `prompts/get` | Client -> Server | Evaluates prompt requests against policy. |
| `initialize` | Client -> Server | Logged. Records capability negotiation. |
| `notifications/*` | Both | Passed through. Logged for correlation. |

Methods not listed above are passed through unmodified but still logged.

## Writing custom policy rules

Policies are defined in TOML at `~/.config/clawdefender/policy.toml`. A policy file contains an ordered list of rules. The first matching rule wins.

### Rule structure

```toml
[[rule]]
action = "deny"                  # "allow", "deny", or "prompt"
tool = "shell_execute"           # Tool name (glob patterns supported)
description = "Block all shell execution"

[[rule]]
action = "prompt"
tool = "filesystem_*"
args.path = "/etc/**"            # Match on argument values (glob patterns)
description = "Ask before accessing system config"

[[rule]]
action = "allow"
tool = "filesystem_read"
args.path = "/home/user/projects/**"
description = "Allow reading project files"

[[rule]]
action = "deny"
tool = "*"
description = "Default deny"
```

### Rule fields

| Field | Required | Description |
|---|---|---|
| `action` | Yes | `allow`, `deny`, or `prompt` |
| `tool` | Yes | Tool name or glob pattern to match |
| `args.<name>` | No | Match on specific argument values (glob patterns) |
| `server` | No | Restrict rule to a specific MCP server name |
| `description` | No | Human-readable explanation (shown in prompts and logs) |

### Evaluation order

1. Rules are evaluated top-to-bottom.
2. The first rule whose `tool` and `args` patterns match the incoming call determines the action.
3. If no rule matches, the default action is `deny`.

### Glob patterns

Both `tool` and `args` fields support glob patterns:

- `*` matches any sequence of characters except `/`
- `**` matches any sequence of characters including `/`
- `?` matches any single character

## Testing policies against fixtures

ClawDefender includes a policy testing mode for verifying rules before deployment:

```bash
# Test a single fixture
clawdefender policy test --policy policy.toml --fixture fixtures/read-ssh-key.json

# Test all fixtures in a directory
clawdefender policy test --policy policy.toml --fixture-dir fixtures/

# Expected output format
clawdefender policy test --policy policy.toml --fixture fixtures/read-ssh-key.json --expect deny
```

### Fixture format

A fixture is a JSON file representing an MCP `tools/call` request:

```json
{
  "method": "tools/call",
  "params": {
    "name": "filesystem_read",
    "arguments": {
      "path": "/home/user/.ssh/id_rsa"
    }
  },
  "expected": "deny"
}
```

The `expected` field is optional. When present, `clawdefender policy test` exits with a non-zero status if the actual decision does not match. This integrates with CI to prevent policy regressions.

## JSON-RPC error codes

When ClawDefender blocks a request, it returns a JSON-RPC error response with the following code:

| Code | Meaning |
|---|---|
| `-32001` | Policy block. The request was denied by a ClawDefender policy rule. The error `data` field may contain `rule` (name of the matching rule) and `action` (`"blocked"` or `"denied"`). |

Standard JSON-RPC error codes (`-32700` parse error, `-32600` invalid request, etc.) are also used where applicable.

Example block response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Blocked by ClawDefender policy",
    "data": {
      "rule": "block_ssh",
      "action": "blocked"
    }
  }
}
```

## Custom policy examples

### Block all network access

```toml
[rules.block_network]
description = "Block all network connections"
action = "block"
message = "Network access is not allowed"
priority = 0

[rules.block_network.match]
event_type = ["connect"]
```

### Allow only project directory

```toml
[rules.allow_project]
description = "Allow reads from project directory"
action = "allow"
message = "Project access allowed"
priority = 0

[rules.allow_project.match]
resource_path = ["/home/user/myproject/**"]

[rules.block_all_other_reads]
description = "Block all other file access"
action = "block"
message = "File access outside project is blocked"
priority = 1

[rules.block_all_other_reads.match]
method = ["resources/read"]
```

### Prompt on all shell execution

```toml
[rules.prompt_shell]
description = "Ask before any shell command"
action = "prompt"
message = "An AI agent wants to run a shell command. Allow?"
priority = 0

[rules.prompt_shell.match]
tool_name = ["shell_*", "exec*", "run_*"]
```

### Audit-only mode (log everything, block nothing)

```toml
[rules.log_everything]
description = "Log all events without blocking"
action = "log"
message = "Logged for audit"
priority = 0

[rules.log_everything.match]
any = true
```

## ClawDefender MCP Server

In addition to the proxy, ClawDefender provides its own MCP server that other MCP servers can call to declare intent, request permission, and report actions. This enables cooperative security participation.

### Starting the MCP Server

```bash
# stdio transport (for direct integration)
clawdefender serve

# HTTP transport on port 3201
clawdefender serve --http --port 3201
```

### Tool Definitions

The MCP server exposes four tools via the standard `tools/list` response:

#### checkIntent

Pre-flight check: will this action be allowed by policy?

```json
{
  "name": "checkIntent",
  "description": "Check whether a planned action is allowed by ClawDefender policy.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "description": { "type": "string", "description": "Human-readable description of what you intend to do" },
      "action_type": { "type": "string", "enum": ["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"] },
      "target": { "type": "string", "description": "Target resource: file path, URL, command, etc." },
      "reason": { "type": "string", "description": "Optional justification" }
    },
    "required": ["description", "action_type", "target"]
  }
}
```

**Response:**
```json
{
  "allowed": true,
  "risk_level": "Low",
  "explanation": "Action allowed: FileRead on '/project/src/main.rs' is permitted by current policy.",
  "policy_rule": "allow"
}
```

When blocked:
```json
{
  "allowed": false,
  "risk_level": "High",
  "explanation": "Action blocked: FileRead on '/home/user/.ssh/id_rsa' is not permitted by current policy.",
  "policy_rule": "block",
  "suggestions": [
    "Use environment variables or a secrets manager instead of reading SSH keys directly"
  ]
}
```

#### requestPermission

Request explicit approval for a resource operation.

```json
{
  "name": "requestPermission",
  "inputSchema": {
    "type": "object",
    "properties": {
      "resource": { "type": "string", "description": "Resource to access (exact path, no wildcards)" },
      "operation": { "type": "string", "enum": ["read", "write", "execute", "delete", "connect"] },
      "justification": { "type": "string", "description": "Why you need this access" },
      "timeout_seconds": { "type": "integer", "default": 30 }
    },
    "required": ["resource", "operation", "justification"]
  }
}
```

**Response:**
```json
{
  "granted": true,
  "scope": "session",
  "expires_at": null
}
```

#### reportAction

Report an action that has already been performed, for audit logging.

```json
{
  "name": "reportAction",
  "inputSchema": {
    "type": "object",
    "properties": {
      "description": { "type": "string", "description": "What happened" },
      "action_type": { "type": "string", "enum": ["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"] },
      "target": { "type": "string", "description": "Target resource" },
      "result": { "type": "string", "enum": ["success", "failure", "partial"] },
      "details": { "type": "object", "description": "Additional details" }
    },
    "required": ["description", "action_type", "target", "result"]
  }
}
```

**Response:**
```json
{
  "recorded": true,
  "event_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### getPolicy

Query the current security policy rules.

```json
{
  "name": "getPolicy",
  "inputSchema": {
    "type": "object",
    "properties": {
      "resource": { "type": "string", "description": "Filter by resource path" },
      "action_type": { "type": "string", "enum": ["file_read", "file_write", "file_delete", "shell_execute", "network_request", "resource_access", "other"] },
      "tool_name": { "type": "string", "description": "Filter by tool name" }
    }
  }
}
```

**Response:**
```json
{
  "rules": [
    {
      "name": "matched_block",
      "description": "Policy evaluation result for query",
      "action": "block",
      "message": "SSH key access is not allowed",
      "priority": 0
    }
  ],
  "default_action": "log"
}
```

### Interaction Protocol

SDK clients communicate with the ClawDefender MCP server using standard JSON-RPC 2.0 over the MCP protocol.

**Typical flow:**

1. Client sends `initialize` request, receives server capabilities
2. Client sends `tools/list` to discover available tools
3. Client calls `getPolicy` to understand current rules
4. Before each action, client calls `checkIntent` via `tools/call`
5. If intent requires approval, client calls `requestPermission`
6. After action completes, client calls `reportAction`

**Example checkIntent call:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "checkIntent",
    "arguments": {
      "description": "Read configuration file",
      "action_type": "file_read",
      "target": "/project/config.toml",
      "reason": "Need to load project settings"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{
      "type": "text",
      "text": "{\"allowed\":true,\"risk_level\":\"Low\",\"explanation\":\"Action allowed...\"}"
    }]
  }
}
```

### Rate Limits

| Tool | Limit | Error Code |
|------|-------|------------|
| `checkIntent` | 100 calls/minute per caller | -32000 |
| `requestPermission` | 10 calls/minute per caller | -32000 |
| `reportAction` | 1000 calls/minute per caller | -32000 |
| `getPolicy` | No limit | -- |

### HTTP Authentication

When using HTTP transport, the MCP server supports Bearer token authentication:

```bash
# Start with auto-generated token
clawdefender serve --http --port 3201

# Token is printed to stderr on startup
# Clients must include: Authorization: Bearer <token>
```
