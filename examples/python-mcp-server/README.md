# Python MCP Server with ClawDefender (Level 3)

A complete example MCP server that integrates all three ClawDefender security
checkpoints, achieving Level 3 Claw Compliance certification.

## What this server does

Exposes three file-operation tools via MCP:

| Tool | Risk | ClawDefender checkpoints |
|---|---|---|
| `read_file` | Low | checkIntent, reportAction |
| `write_file` | Medium | checkIntent, requestPermission, reportAction |
| `list_directory` | Low | checkIntent, reportAction |

## Security checkpoints explained

### 1. checkIntent (before action)

Before performing any operation, the server asks ClawDefender whether the
action is allowed by the active policy:

```python
intent = await claw.check_intent(
    description="Read file: /tmp/data.txt",
    action_type="file_read",
    target="/tmp/data.txt",
    reason="User requested file contents",
)
if not intent.allowed:
    return blocked_response(intent.explanation)
```

If the policy blocks this action, the server returns a message to the user
explaining why -- the file is never touched.

### 2. requestPermission (before sensitive writes)

For write operations, the server requests explicit permission. This may trigger
a user-facing prompt in the MCP client (e.g., Claude Desktop shows a dialog):

```python
perm = await claw.request_permission(
    resource="/tmp/output.txt",
    operation="write",
    justification="Writing 42 bytes to /tmp/output.txt",
)
if not perm.granted:
    return denied_response()
```

### 3. reportAction (after action)

After every operation (success or failure), the server reports what happened
so ClawDefender can maintain an audit log:

```python
await claw.report_action(
    description="Read file: /tmp/data.txt",
    action_type="file_read",
    target="/tmp/data.txt",
    result="success",
)
```

## Graceful degradation

If the `clawdefender-sdk` package is not installed or the ClawDefender daemon
is not running, this server continues to function normally. All security
checkpoints are wrapped in `if CLAWDEFENDER_AVAILABLE:` guards.

This means users who have not installed ClawDefender can still use your server.

## Setup

```bash
# Install dependencies
pip install -e .

# Run the server (stdio mode, for MCP clients)
python server.py
```

## Using with ClawDefender

```bash
# Option A: Wrap the server for Claude Desktop
clawdefender wrap example-file-operations

# Option B: Run directly with the proxy
clawdefender proxy -- python server.py
```

## Certifying

```bash
clawdefender certify .
# Expected output:
#   Checking example-file-operations...
#   [PASS] clawdefender.toml manifest found
#   [PASS] All tools declare risk levels
#   [PASS] checkIntent called before all tool actions
#   [PASS] requestPermission called before write operations
#   [PASS] reportAction called after all tool actions
#   Result: Level 3 Claw Compliant
```

## Manifest

The `clawdefender.toml` file declares:

- **Permissions required** -- which directories the server reads/writes
- **Tools exposed** -- each tool with its risk level and required permissions
- **Compliance level** -- Level 3 (full SDK integration)

This manifest is used by `clawdefender certify` and displayed to users during
installation so they know what the server will do before granting access.
