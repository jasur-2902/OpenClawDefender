# Cursor Integration

ClawDefender integrates with Cursor by wrapping its MCP servers, intercepting
all tool calls before they reach the server.

## Configuration

Cursor stores its MCP server configuration at:

```
~/.cursor/mcp.json
```

The format is identical to Claude Desktop's configuration.

## Wrapping a server

```bash
# Auto-detect Cursor config and wrap a server
clawdefender wrap --client cursor filesystem

# Or specify the config path directly
clawdefender wrap --config ~/.cursor/mcp.json filesystem
```

This rewrites the Cursor MCP config so that ClawDefender sits between Cursor
and the MCP server.

## Cursor-specific notes

### Agent mode

Cursor's Agent mode makes extensive use of MCP tools for file editing, terminal
commands, and code search. When wrapping these servers with ClawDefender:

- **File editing tools** -- Consider using the `development` policy template
  which allows reads in project directories and prompts on writes.
- **Terminal tools** -- Cursor's terminal integration may trigger frequent
  prompt requests. Use a session-scoped allow rule for known-safe commands.
- **Code search** -- Read-only operations are typically safe to allow.

### Recommended policy

```toml
# Allow reads in the active project directory
[rules.allow_project_reads]
description = "Allow file reads in the active project"
action = "allow"
priority = 10
[rules.allow_project_reads.match]
resource_path = ["~/Projects/**", "~/workspace/**"]

# Prompt on file writes
[rules.prompt_writes]
description = "Prompt before writing files"
action = "prompt"
message = "Cursor agent wants to write a file. Allow?"
priority = 20
[rules.prompt_writes.match]
tool_name = ["write_file", "create_file", "edit_file"]

# Prompt on shell execution
[rules.prompt_shell]
description = "Prompt before shell commands"
action = "prompt"
message = "Cursor agent wants to run a command. Allow?"
priority = 25
[rules.prompt_shell.match]
tool_name = ["run_command", "execute", "shell", "bash"]
```

## Restart Cursor

After wrapping, restart Cursor for the configuration changes to take effect.

## Unwrapping

```bash
clawdefender unwrap --client cursor filesystem
```
