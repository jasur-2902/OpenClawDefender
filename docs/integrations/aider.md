# Aider Integration

ClawDefender can monitor and control tool calls made by Aider when it operates
through MCP servers.

## How Aider uses MCP

Aider can connect to MCP servers for file editing, git operations, and shell
command execution. When configured with MCP, Aider sends tool calls through
the standard MCP JSON-RPC protocol.

## Wrapping with ClawDefender

Aider's MCP configuration can be wrapped using `clawdefender proxy`:

```bash
# Instead of running:
aider --mcp-server "npx -y @modelcontextprotocol/server-filesystem /home/user"

# Run with ClawDefender:
aider --mcp-server "clawdefender proxy -- npx -y @modelcontextprotocol/server-filesystem /home/user"
```

For persistent configuration, update Aider's config file to use the wrapped
command.

## Recommended policies for Aider

Aider primarily performs file editing and git operations. The following policy
covers typical Aider usage:

```toml
[metadata]
name = "aider"
version = "0.1.0"
description = "Policy for Aider AI coding assistant"

# Allow file reads in the project directory
[rules.allow_project_reads]
description = "Allow Aider to read project files"
action = "allow"
priority = 10
[rules.allow_project_reads.match]
resource_path = [".//**"]

# Prompt before file writes
[rules.prompt_file_writes]
description = "Prompt before Aider writes files"
action = "prompt"
message = "Aider wants to modify a file. Allow?"
priority = 20
[rules.prompt_file_writes.match]
tool_name = ["write_file", "create_file", "edit_file"]

# Allow git read operations
[rules.allow_git_reads]
description = "Allow Aider to read git state"
action = "allow"
priority = 15
[rules.allow_git_reads.match]
tool_name = ["git_status", "git_log", "git_diff", "git_show"]

# Prompt before git writes
[rules.prompt_git_writes]
description = "Prompt before Aider commits or pushes"
action = "prompt"
message = "Aider wants to modify the git repository. Allow?"
priority = 25
[rules.prompt_git_writes.match]
tool_name = ["git_commit", "git_push", "git_add"]

# Prompt on shell execution
[rules.prompt_shell]
description = "Prompt before shell commands"
action = "prompt"
message = "Aider wants to execute a shell command. Allow?"
priority = 30
[rules.prompt_shell.match]
tool_name = ["run_command", "execute", "shell", "bash"]

# Block credential access
[rules.block_credentials]
description = "Block access to credentials"
action = "block"
priority = 5
[rules.block_credentials.match]
resource_path = ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**"]
```

## Monitoring Aider sessions

```bash
# Watch Aider tool calls in real time
clawdefender log --follow

# Review what Aider did in a session
clawdefender log --since "1 hour ago"
```
