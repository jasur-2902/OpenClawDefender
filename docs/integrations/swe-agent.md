# SWE-agent Integration

ClawDefender can monitor and control actions taken by SWE-agent, an AI agent
designed to fix GitHub issues by editing code and running tests.

## SWE-agent patterns

SWE-agent typically:

1. Reads repository files to understand code structure
2. Edits source files to implement fixes
3. Runs test commands to verify changes
4. Uses git to commit and create patches

These operations map to file read/write, shell execution, and git tool calls
in MCP.

## File editing and command execution monitoring

SWE-agent makes heavy use of file editing and shell commands. ClawDefender
evaluates each of these against your policy:

```bash
# Wrap the MCP server SWE-agent connects to
clawdefender proxy -- <swe-agent-mcp-server-command>
```

## Recommended policies

```toml
[metadata]
name = "swe-agent"
version = "0.1.0"
description = "Policy for SWE-agent"

# Allow reads across the repository
[rules.allow_repo_reads]
description = "Allow reading repository files"
action = "allow"
priority = 10
[rules.allow_repo_reads.match]
resource_path = ["/workspace/**", "/repo/**"]

# Allow file writes within the repository
[rules.allow_repo_writes]
description = "Allow editing repository files"
action = "allow"
priority = 15
[rules.allow_repo_writes.match]
resource_path = ["/workspace/**", "/repo/**"]
tool_name = ["write_file", "edit_file", "create_file"]

# Allow common test/build commands
[rules.allow_test_commands]
description = "Allow test and build commands"
action = "allow"
priority = 20
[rules.allow_test_commands.match]
tool_name = ["run_command", "execute", "shell"]
# Note: Further restrict by command content in advanced policies

# Prompt on git push operations
[rules.prompt_git_push]
description = "Prompt before pushing to remote"
action = "prompt"
message = "SWE-agent wants to push to a remote. Allow?"
priority = 12
[rules.prompt_git_push.match]
tool_name = ["git_push"]

# Block credential access
[rules.block_credentials]
description = "Block credential access"
action = "block"
priority = 5
[rules.block_credentials.match]
resource_path = ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.config/gh/**"]

# Block network operations (SWE-agent should not need network)
[rules.block_network]
description = "Block network access"
action = "block"
priority = 8
[rules.block_network.match]
tool_name = ["fetch", "http_request", "curl", "wget"]

# Log everything else
[rules.log_all]
description = "Log unmatched events"
action = "log"
priority = 1000
[rules.log_all.match]
any = true
```

## Monitoring

```bash
# Watch SWE-agent actions in real time
clawdefender log --follow

# Review actions taken on a specific file
clawdefender log --filter "target=src/main.py"
```
