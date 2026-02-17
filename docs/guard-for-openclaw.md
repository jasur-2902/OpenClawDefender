# ClawDefender Guard for OpenClaw Bots

This guide explains how to add self-protection to your OpenClaw bot using the AgentGuard.

## Mental model: the seatbelt analogy

Think of the AgentGuard as a seatbelt for your bot. Your bot could operate without it, but if something goes wrong (a prompt injection, an unexpected tool call, a rogue plugin), the guard limits the damage.

Unlike external firewalls that protect systems *from* the agent, the AgentGuard is carried *by* the agent. The agent declares its own boundaries upfront and the guard enforces them, even if the agent's reasoning is later manipulated.

Key properties:
- **Self-declared**: The agent (or its operator) specifies what it should be able to do.
- **Fail-closed**: If the guard cannot verify an operation, it blocks it.
- **Non-bypassable at the API level**: The agent checks every tool call through the guard before execution.
- **Observable**: All blocked operations are logged and available via stats.

## Integration steps

### Step 1: Install the package

```bash
pip install clawdefender-agent
```

### Step 2: Create the guard

Define permissions based on what your bot actually needs:

```python
from clawdefender.agent import AgentGuard

guard = AgentGuard(
    name="my-openclaw-bot",
    allowed_paths=["~/my-project/**"],
    allowed_tools=["read_file", "write_file", "list_directory"],
    blocked_paths=["~/.ssh/", "~/.aws/"],
    network_allowlist=["api.anthropic.com"],
    shell_policy="deny",
    mode="enforce",
)
```

### Step 3: Activate before any agent work

```python
guard.activate(fallback=True)
```

### Step 4: Check every tool call

Before your bot executes a tool, check it against the guard:

```python
result = guard.check_action("file_read", target_path)
if not result.allowed:
    # Do not proceed with this operation
    return f"Operation blocked: {result.reason}"
```

### Step 5: Deactivate on shutdown

```python
guard.deactivate()
```

Or use the context manager:

```python
with AgentGuard(name="my-bot", ...) as guard:
    # All work happens here
    pass
# Guard auto-deactivates
```

## Recommended permissions for common bot patterns

### Code assistant bot

Reads and writes code in a project directory. Needs network for the LLM API only.

```python
AgentGuard(
    name="code-assistant",
    allowed_paths=["~/my-project/**"],
    allowed_tools=["read_file", "write_file", "list_directory", "search_files"],
    network_allowlist=["api.anthropic.com"],
    shell_policy="deny",
)
```

### Research bot

Reads files and accesses multiple APIs. No file writing.

```python
AgentGuard(
    name="researcher",
    allowed_paths=["~/research-data/**"],
    allowed_tools=["read_file", "list_directory", "search_files"],
    network_allowlist=["api.anthropic.com", "api.semanticscholar.org"],
    shell_policy="deny",
)
```

### Build bot

Needs shell access for running build commands, but only specific ones.

```python
AgentGuard(
    name="build-bot",
    allowed_paths=["~/my-project/**"],
    allowed_tools=["read_file", "write_file", "list_directory"],
    network_allowlist=["api.anthropic.com", "registry.npmjs.org"],
    shell_policy="allowlist",
    allowed_commands=["npm install", "npm run build", "npm test"],
)
```

### Sandbox bot

Pure computation with no external access.

```python
AgentGuard(
    name="sandbox-bot",
    allowed_paths=[],
    allowed_tools=[],
    network_allowlist=[],
    shell_policy="deny",
)
```

## Handling blocked operations

When an operation is blocked, the guard returns a `CheckResult` with `allowed=False` and a `reason` string. Your bot should handle this gracefully:

```python
result = guard.check_action("file_read", "/etc/passwd")
if not result.allowed:
    # Option 1: Skip and explain to the user
    print(f"I cannot read that file: {result.reason}")

    # Option 2: Log and continue with alternative approach
    logger.warning("Blocked: %s on %s — %s", "file_read", "/etc/passwd", result.reason)

    # Option 3: Raise to abort the current task
    raise PermissionError(result.reason)
```

Never ignore blocked operations. They indicate either:
1. A legitimate permission gap (update your guard config), or
2. A potential security issue (the bot tried something unexpected).

## Development workflow with monitor mode

During development, use monitor mode to discover what your bot needs:

```python
# 1. Start in monitor mode
guard = AgentGuard(name="my-bot", mode="monitor")
guard.activate(fallback=True)

# 2. Run your bot's normal workload — nothing is blocked
run_my_bot()

# 3. Check what the bot tried to do
suggestions = guard.suggest_permissions()
print(suggestions)
# {'file_read': ['/path/to/files/...'], 'network_hosts': ['api.anthropic.com'], ...}

# 4. Review stats for unexpected operations
stats = guard.stats()
print(f"Total checks: {stats.checked_count}")

# 5. Configure enforce mode with the discovered permissions
guard.deactivate()
```

This workflow ensures you grant the minimum permissions your bot actually needs, rather than guessing upfront.
