# MCP Client Compatibility Matrix

## Supported Clients

| Feature | Claude Desktop | Cursor | VS Code | Windsurf |
|---------|---------------|--------|---------|----------|
| Config location (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.cursor/mcp.json` | `~/.vscode/mcp.json` | `~/.codeium/windsurf/mcp_config.json` |
| Config location (Linux) | `~/.config/Claude/claude_desktop_config.json` | `~/.cursor/mcp.json` | `~/.vscode/mcp.json` | `~/.codeium/windsurf/mcp_config.json` |
| Servers JSON key | `mcpServers` | `mcpServers` or `servers` | `mcpServers` | `mcpServers` |
| Workspace-level config | No | `.cursor/mcp.json` | `.vscode/mcp.json` | No |
| Auto-detection | Yes | Yes | Yes | Yes |
| `--client` flag | `claude` | `cursor` | `vscode` | `windsurf` |
| Wrap/unwrap support | Yes | Yes | Yes | Yes |

## Config File Format

All supported clients use JSON config files with the same general structure:

```json
{
  "mcpServers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@mcp/server"],
      "env": {
        "KEY": "value"
      }
    }
  }
}
```

### Cursor Variant

Some Cursor versions use `"servers"` instead of `"mcpServers"`:

```json
{
  "servers": {
    "server-name": {
      "command": "npx",
      "args": ["-y", "@mcp/server"]
    }
  }
}
```

ClawDefender auto-detects which key is in use, preferring `"mcpServers"` when both exist.

## MCP Protocol Details

### Protocol Version

All clients use the MCP protocol over stdio JSON-RPC 2.0. The protocol version is negotiated during the `initialize` handshake.

### Initialize Handshake

The client sends an `initialize` request, and the server responds with capabilities. ClawDefender's proxy passes this through transparently (Classification::Pass).

```json
// Client -> Server
{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"capabilities":{}}}

// Server -> Client (passed through)
{"jsonrpc":"2.0","id":0,"result":{"capabilities":{"tools":{}}}}
```

### Response Timeout Behavior

| Client | Default Timeout | Notes |
|--------|----------------|-------|
| Claude Desktop | ~60s | Generous timeout, suitable for interactive prompts |
| Cursor | ~30s | Shorter timeout; inline completions may timeout faster |
| VS Code | ~30s | Depends on extension implementation |
| Windsurf | ~30s | Similar to Cursor |

ClawDefender's default `prompt_timeout` is 30 seconds, which is compatible with all clients. For Cursor, if ClawDefender needs user approval (Prompt action), the approval must arrive before the client's own timeout.

### Error Handling

When ClawDefender blocks a request, it returns a JSON-RPC error response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "Blocked by ClawDefender policy"
  }
}
```

Error code `-32001` is in the server-defined range (-32000 to -32099). Client display behavior:

| Client | Error Display |
|--------|--------------|
| Claude Desktop | Shows error in chat as a failed tool call |
| Cursor | Shows error in output panel; inline completion silently fails |
| VS Code | Shows error in output panel, may show notification |
| Windsurf | Shows error in output panel |

### Batch Request Behavior

JSON-RPC 2.0 supports batch requests (array of messages). ClawDefender processes each message individually in the order received. If one message in a sequence is blocked, others are still forwarded/evaluated independently.

### Keepalive / Ping

The `ping` method is classified as `Pass` and forwarded transparently. All clients may send periodic pings to check server health. ClawDefender does not interfere with these.

### Reconnection Behavior

| Client | Reconnection | Notes |
|--------|-------------|-------|
| Claude Desktop | Restarts the MCP server process | Full restart on disconnect |
| Cursor | Restarts the MCP server process | May retry more aggressively |
| VS Code | Depends on extension | Most extensions restart on disconnect |
| Windsurf | Restarts the MCP server process | Similar to Cursor |

When ClawDefender's proxy process exits (or the wrapped server exits), the client will restart the entire command, which re-launches ClawDefender's proxy.

## Client-Specific Quirks

### Claude Desktop
- Config path uses macOS `Application Support` directory (no Linux support officially)
- Uses `mcpServers` key exclusively
- Most generous timeouts
- First-class MCP support

### Cursor
- May use `"servers"` key instead of `"mcpServers"` in some versions
- Sends MCP requests more rapidly (inline completions trigger tool calls)
- Shorter timeouts; prompt-based policies may cause timeouts during rapid typing
- Supports workspace-level `.cursor/mcp.json`

### VS Code
- MCP support is via extensions (e.g., Copilot MCP, Continue)
- Config may be in `~/.vscode/mcp.json` or extension-specific settings
- Supports workspace-level `.vscode/mcp.json`

### Windsurf
- Config at `~/.codeium/windsurf/mcp_config.json`
- Similar behavior to Cursor
- Uses `mcpServers` key

## Wrap/Unwrap Behavior

When ClawDefender wraps a server, it:

1. Backs up the config file to `*.json.bak`
2. Replaces the `command` with the absolute path to `clawdefender`
3. Sets `args` to `["proxy", "--", <original_command>, <original_args...>]`
4. Stores the original config in `_clawdefender_original`

The absolute path is resolved at wrap-time so the config works regardless of the client's PATH environment (MCP clients often do not inherit shell PATH).

Unwrap reverses this: restores `command` and `args` from `_clawdefender_original` and removes the key.
