# MCP Protocol Reference

This document describes how ClawAI interacts with the Model Context Protocol (MCP) and serves as a reference for developers extending ClawAI or writing custom policies.

## How `clawai wrap` works

When you run `clawai wrap <server-name>`, ClawAI modifies the MCP client configuration so that instead of launching the MCP server directly, the client launches ClawAI, which in turn launches the real server.

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
      "command": "clawai",
      "args": ["proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    }
  }
}
```

ClawAI spawns the real server as a child process, connects to its stdin/stdout, and sits in the middle of all JSON-RPC communication.

For remote (HTTP/SSE) MCP servers, ClawAI acts as a reverse proxy, forwarding requests after policy evaluation.

## Intercepted JSON-RPC methods

ClawAI intercepts and evaluates the following MCP methods:

| Method | Direction | What ClawAI does |
|---|---|---|
| `tools/call` | Client -> Server | **Primary enforcement point.** Evaluates tool name and arguments against policy rules. May allow, deny, or prompt. |
| `tools/list` | Server -> Client | Logged for audit. ClawAI records the declared tool set for a server, used later for correlation. |
| `resources/read` | Client -> Server | Evaluates the resource URI against policy rules. Can restrict which resources an agent accesses. |
| `resources/list` | Server -> Client | Logged for audit. Records available resources. |
| `sampling/createMessage` | Server -> Client | Evaluates sampling requests. Can block or modify prompts that match injection patterns. |
| `prompts/get` | Client -> Server | Evaluates prompt requests against policy. |
| `initialize` | Client -> Server | Logged. Records capability negotiation. |
| `notifications/*` | Both | Passed through. Logged for correlation. |

Methods not listed above are passed through unmodified but still logged.

## Writing custom policy rules

Policies are defined in TOML at `~/.config/clawai/policy.toml`. A policy file contains an ordered list of rules. The first matching rule wins.

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

ClawAI includes a policy testing mode for verifying rules before deployment:

```bash
# Test a single fixture
clawai policy test --policy policy.toml --fixture fixtures/read-ssh-key.json

# Test all fixtures in a directory
clawai policy test --policy policy.toml --fixture-dir fixtures/

# Expected output format
clawai policy test --policy policy.toml --fixture fixtures/read-ssh-key.json --expect deny
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

The `expected` field is optional. When present, `clawai policy test` exits with a non-zero status if the actual decision does not match. This integrates with CI to prevent policy regressions.
