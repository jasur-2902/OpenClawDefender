# OpenHands Integration

ClawDefender can monitor and control actions taken by OpenHands (formerly
OpenDevin), an open-source AI software development agent.

## OpenHands architecture

OpenHands runs AI agents that can:

- Edit files in a workspace (often inside a Docker container)
- Execute shell commands
- Browse the web
- Interact with GitHub

When OpenHands uses MCP servers for these operations, ClawDefender can
intercept and evaluate each action against your security policy.

## How to monitor with ClawDefender

### Container-based deployments

If OpenHands runs inside a container, install ClawDefender inside the container
or run it as a sidecar that proxies MCP traffic:

```bash
# In your Dockerfile or container setup:
# Install ClawDefender
curl -sSL https://clawdefender.dev/install.sh | sh

# Wrap the MCP server that OpenHands connects to
clawdefender proxy -- <original-server-command>
```

### Local deployments

For local OpenHands installations, wrap the MCP server in the agent
configuration:

```bash
clawdefender proxy -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

## Recommended policies

OpenHands performs aggressive file editing and shell execution. Use a policy
that allows workspace operations but blocks access to sensitive paths:

```toml
[metadata]
name = "openhands"
version = "0.1.0"
description = "Policy for OpenHands AI agent"

# Allow all operations within the workspace
[rules.allow_workspace]
description = "Allow all file operations in workspace"
action = "allow"
priority = 10
[rules.allow_workspace.match]
resource_path = ["/workspace/**"]

# Prompt on shell execution
[rules.prompt_shell]
description = "Prompt before shell commands"
action = "prompt"
message = "OpenHands wants to execute a command. Allow?"
priority = 20
[rules.prompt_shell.match]
tool_name = ["run_command", "execute", "shell", "bash"]

# Block credential and system access
[rules.block_credentials]
description = "Block credential access"
action = "block"
priority = 5
[rules.block_credentials.match]
resource_path = ["~/.ssh/**", "~/.aws/**", "/etc/shadow", "/etc/passwd"]

# Block network tools by default
[rules.prompt_network]
description = "Prompt on network operations"
action = "prompt"
message = "OpenHands wants to make a network request. Allow?"
priority = 15
[rules.prompt_network.match]
tool_name = ["fetch", "http_request", "curl", "wget", "browse"]

# Log everything else
[rules.log_all]
description = "Log unmatched events"
action = "log"
priority = 1000
[rules.log_all.match]
any = true
```

## Monitoring sessions

```bash
# Live monitoring of OpenHands actions
clawdefender log --follow

# Export audit log for review
clawdefender log --format json --since "today" > openhands-audit.json
```
