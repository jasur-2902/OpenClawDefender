# ClawDefender Python SDK

Python SDK for integrating [ClawDefender](https://github.com/clawai/clawdefender) guardrails into MCP server tools. ClawDefender enforces safety policies on AI agent actions — file access, shell execution, network requests, and more.

## Installation

```bash
pip install clawdefender-sdk
```

## Quick Start

```python
from clawdefender import ClawDefender

claw = ClawDefender()
result = claw.check_intent(
    description="Read user config",
    action_type="file_read",
    target="~/.config/app.yml",
)
print(result.allowed, result.risk_level)
```

## Connection Modes

The SDK communicates with ClawDefender via the MCP protocol.

| Mode    | Description                                         |
| ------- | --------------------------------------------------- |
| `auto`  | Try HTTP daemon first, fall back to stdio (default) |
| `http`  | Connect to running daemon at `http://127.0.0.1:3201`|
| `stdio` | Spawn `clawdefender serve` subprocess               |

```python
# Explicit HTTP
claw = ClawDefender(mode="http", http_url="http://localhost:3201")

# Explicit stdio with custom binary
claw = ClawDefender(mode="stdio", command="/usr/local/bin/clawdefender")
```

### Fail-Open Behaviour

By default the SDK operates in **fail-open** mode: if ClawDefender is not installed or the daemon is not running, all `check_intent` calls return `allowed=True` and the host MCP server continues working normally. This ensures your server never crashes due to a missing guardrail dependency.

```python
# Disable fail-open (strict mode — raises on connection failure)
claw = ClawDefender(fail_open=False)
```

## API Reference

### `ClawDefender`

#### `check_intent(description, action_type, target, reason=None) -> CheckIntentResponse`

Check whether an intended action is allowed by policy.

```python
resp = claw.check_intent(
    description="Delete temp files",
    action_type="file_delete",
    target="/tmp/*.log",
)
if not resp.allowed:
    print(resp.explanation, resp.suggestions)
```

#### `request_permission(resource, operation, justification, timeout_seconds=30) -> RequestPermissionResponse`

Request explicit user permission for a sensitive operation.

```python
resp = claw.request_permission(
    resource="/etc/hosts",
    operation="write",
    justification="Adding development hostname",
)
if resp.granted:
    # proceed
    ...
```

#### `report_action(description, action_type, target, result, details=None) -> ReportActionResponse`

Report a completed action for the audit log.

```python
claw.report_action(
    description="Wrote config",
    action_type="file_write",
    target="/app/config.yml",
    result="success",
    details={"bytes_written": 512},
)
```

#### `get_policy(resource=None, action_type=None, tool_name=None) -> GetPolicyResponse`

Query active policy rules.

```python
policy = claw.get_policy(action_type="shell_execute")
print(policy.default_action, policy.rules)
```

### Async API

Every method has an async variant prefixed with `a`:

```python
resp = await claw.acheck_intent("Read secret", "file_read", "/etc/shadow")
resp = await claw.arequest_permission("/tmp/out", "write", "Build output")
resp = await claw.areport_action("Wrote file", "file_write", "/tmp/out", "success")
resp = await claw.aget_policy()
```

## Decorator Pattern

### `@requires_permission`

Automatically request permission before a function runs. Raises `PermissionDenied` if denied.

```python
from clawdefender import requires_permission, PermissionDenied

@requires_permission(operation="execute", justification="Running user command")
async def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()

try:
    output = await run_command("ls -la")
except PermissionDenied as e:
    print(f"Blocked: {e}")
```

The decorator inspects function parameter names (`path`, `file`, `command`, `url`) to auto-detect the target. Use `target_param` to override:

```python
@requires_permission(operation="connect", target_param="endpoint")
def call_api(endpoint: str, payload: dict) -> dict:
    ...
```

### `@reports_action`

Automatically report success/failure after a function completes.

```python
from clawdefender import reports_action

@reports_action(action_type="file_write")
def write_file(path: str, content: str) -> None:
    Path(path).write_text(content)
```

Both decorators work with sync and async functions.

## Context Manager

For fine-grained control, use `guarded_action`:

```python
async with claw.guarded_action(
    description="Deploy to production",
    action_type="network_request",
    target="https://production.example.com/deploy",
) as guard:
    if guard.allowed:
        await deploy()
        guard.report_success(details={"status": 200})
    else:
        logger.warning(f"Blocked: {guard.explanation}")
```

Also works synchronously:

```python
with claw.guarded_action("Write config", "file_write", "/etc/app.conf") as guard:
    if guard.allowed:
        write_config()
```

If an exception occurs inside the block, the action is automatically reported as a failure.

## Types

All enums and response dataclasses are importable from `clawdefender`:

```python
from clawdefender import (
    ActionType,       # file_read, file_write, shell_execute, ...
    RiskLevel,        # Low, Medium, High, Critical
    Operation,        # read, write, execute, delete, connect
    PermissionScope,  # once, session, permanent
    ActionResult,     # success, failure, partial
)
```

## Examples

### MCP Server Tool with Guardrails

```python
from clawdefender import ClawDefender, requires_permission, reports_action

claw = ClawDefender()

@requires_permission(operation="execute", justification="User requested shell command")
@reports_action(action_type="shell_execute")
async def execute_tool(command: str) -> str:
    proc = await asyncio.create_subprocess_shell(
        command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return stdout.decode()
```

### Policy-Aware File Operations

```python
async def safe_write(path: str, content: str) -> None:
    async with claw.guarded_action("Write file", "file_write", path) as guard:
        if guard.allowed:
            Path(path).write_text(content)
        else:
            raise RuntimeError(f"Write blocked: {guard.explanation}")
```

## Development

```bash
cd sdks/python
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0
