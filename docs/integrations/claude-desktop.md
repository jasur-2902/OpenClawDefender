# Claude Desktop Integration

ClawDefender integrates with Claude Desktop by wrapping MCP servers in its
security proxy. Every tool call from Claude passes through ClawDefender's
policy engine before reaching the server.

ClawDefender supports both configuration formats used by Claude Desktop:

- **Traditional config** (`mcpServers` in `claude_desktop_config.json` or `config.json`)
- **DXT extensions** (`extensions-installations.json`) — used by Claude Desktop for extensions installed from the extension registry

## Configuration

### Traditional MCP servers

Claude Desktop stores its MCP server configuration at:

```
~/Library/Application Support/Claude/claude_desktop_config.json
```

Or in newer versions:

```
~/Library/Application Support/Claude/config.json
```

On Linux:

```
~/.config/Claude/claude_desktop_config.json
```

### DXT extensions

Claude Desktop installs extensions from the extension registry into:

```
~/Library/Application Support/Claude/extensions-installations.json
```

Each extension's MCP config is nested at
`extensions.<id>.manifest.server.mcp_config`. ClawDefender discovers and wraps
these automatically.

## Wrapping a server

```bash
# Wrap a traditional MCP server
clawdefender wrap filesystem

# Wrap a DXT extension (by name or extension id)
clawdefender wrap chrome-control
clawdefender wrap "Control Chrome"
clawdefender wrap ant.dir.ant.anthropic.chrome-control

# Explicitly target Claude Desktop
clawdefender wrap filesystem --client claude
```

ClawDefender tries the traditional `mcpServers` config first. If the server is
not found there, it searches DXT extensions by name, display name, or extension
id (case-insensitive).

### Traditional config — before and after

Before wrapping:

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

After wrapping:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/usr/local/bin/clawdefender",
      "args": ["proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
      "_clawdefender_original": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
      }
    }
  }
}
```

### DXT extension — before and after

Before wrapping:

```json
{
  "manifest": {
    "server": {
      "mcp_config": {
        "command": "node",
        "args": ["${__dirname}/server/index.js"]
      }
    }
  }
}
```

After wrapping:

```json
{
  "manifest": {
    "server": {
      "mcp_config": {
        "command": "/usr/local/bin/clawdefender",
        "args": ["proxy", "--", "node", "${__dirname}/server/index.js"],
        "_clawdefender_original": {
          "command": "node",
          "args": ["${__dirname}/server/index.js"]
        }
      }
    }
  }
}
```

The `${__dirname}` token is preserved as-is — Claude Desktop resolves it at
runtime before spawning the process.

ClawDefender creates a `.bak` backup of the config file before modifying it.

## Restart Claude Desktop

After wrapping, restart Claude Desktop for the changes to take effect. You can
do this from the system tray icon or by quitting and relaunching the app.

## User experience

When ClawDefender is active:

1. **Allowed actions** pass through silently. You will not notice any difference.
2. **Prompted actions** trigger a notification from the ClawDefender menubar app.
   You see what the agent wants to do and can approve or deny it.
3. **Blocked actions** are denied before they reach the server. Claude receives
   an error response explaining that the action was blocked by policy.

## Recommended policies for common servers

### @modelcontextprotocol/server-filesystem

```toml
# Allow reads in your project directories
[rules.allow_project_reads]
description = "Allow file reads in project dirs"
action = "allow"
priority = 10
[rules.allow_project_reads.match]
resource_path = ["~/Projects/**", "~/workspace/**"]

# Prompt before any file write
[rules.prompt_file_writes]
description = "Prompt before file writes"
action = "prompt"
message = "Claude wants to write a file. Allow?"
priority = 20
[rules.prompt_file_writes.match]
tool_name = ["write_file", "create_file", "edit_file"]

# Block access to dotfiles and credentials
[rules.block_dotfiles]
description = "Block access to dotfiles"
action = "block"
priority = 5
[rules.block_dotfiles.match]
resource_path = ["~/.*/**"]
```

### @modelcontextprotocol/server-git

```toml
# Allow read-only git operations
[rules.allow_git_reads]
description = "Allow git status, log, diff"
action = "allow"
priority = 10
[rules.allow_git_reads.match]
tool_name = ["git_status", "git_log", "git_diff"]

# Prompt before commits and pushes
[rules.prompt_git_writes]
description = "Prompt before git writes"
action = "prompt"
message = "Claude wants to modify the git repository. Allow?"
priority = 20
[rules.prompt_git_writes.match]
tool_name = ["git_commit", "git_push", "git_checkout", "git_reset"]
```

### @modelcontextprotocol/server-fetch

```toml
# Allow fetching from known documentation sites
[rules.allow_docs_fetch]
description = "Allow fetching documentation"
action = "allow"
priority = 10
[rules.allow_docs_fetch.match]
tool_name = ["fetch"]
# Note: URL filtering depends on server argument names

# Prompt on all other fetches
[rules.prompt_fetch]
description = "Prompt before fetching URLs"
action = "prompt"
message = "Claude wants to fetch a URL. Allow?"
priority = 20
[rules.prompt_fetch.match]
tool_name = ["fetch"]
```

### @modelcontextprotocol/server-brave-search

```toml
# Allow search (read-only, low risk)
[rules.allow_search]
description = "Allow web searches"
action = "allow"
priority = 10
[rules.allow_search.match]
tool_name = ["brave_web_search", "brave_local_search"]
```

## Unwrapping

To remove ClawDefender from a server:

```bash
# Unwrap a traditional MCP server
clawdefender unwrap filesystem

# Unwrap a DXT extension
clawdefender unwrap chrome-control
```

This restores the original server configuration from the `_clawdefender_original`
data stored during wrapping. A `.bak` backup is also created before unwrapping.

## Viewing the audit log

```bash
# Live tail of all events
clawdefender log --follow

# Filter to Claude Desktop events
clawdefender log --server filesystem
```

## Troubleshooting

**Claude Desktop does not start after wrapping:**
- Check that `clawdefender` is in your PATH (the `wrap` command writes an absolute path to avoid this issue)
- Run `clawdefender unwrap <server>` to restore the original config
- Check the backup at `claude_desktop_config.json.bak` or `extensions-installations.json.bak`

**Tool calls are slow:**
- ClawDefender adds minimal latency (<5ms for policy evaluation)
- If prompts are enabled, latency depends on how fast you respond

**Server not found:**
- For traditional servers, make sure the name matches the key in `mcpServers` exactly
- For DXT extensions, you can use the extension name, display name, or full id (e.g. `chrome-control`, `"Control Chrome"`, or `ant.dir.ant.anthropic.chrome-control`)
- Run `clawdefender wrap <name> --client claude` to search only Claude Desktop configs

**Cannot find the config file:**
- Traditional configs: `~/Library/Application Support/Claude/claude_desktop_config.json` or `config.json`
- DXT extensions: `~/Library/Application Support/Claude/extensions-installations.json`
