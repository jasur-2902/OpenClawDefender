"""
Test MCP server exercising the full ClawDefender Python SDK.

Demonstrates all four SDK checkpoints:
  1. getPolicy     -- on startup, query active policy
  2. checkIntent   -- before file reads
  3. requestPermission -- before shell execution
  4. reportAction  -- after every action

Graceful degradation: if ClawDefender is unavailable, falls back to allow-all.

Run with:
    python test_server.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# ClawDefender SDK — graceful degradation
# ---------------------------------------------------------------------------

CLAWDEFENDER_AVAILABLE = False
claw = None

try:
    from clawdefender import ClawDefender

    claw = ClawDefender(fail_open=True)
    CLAWDEFENDER_AVAILABLE = True
except ImportError:
    pass


async def startup_policy_check() -> dict[str, Any]:
    """Query policy on startup. Returns the policy or a fallback."""
    if not CLAWDEFENDER_AVAILABLE or claw is None:
        return {"status": "unavailable", "default_action": "allow"}
    try:
        policy = claw.get_policy()
        return {
            "status": "connected",
            "rules": policy.rules,
            "default_action": policy.default_action,
        }
    except Exception as exc:
        return {"status": "degraded", "error": str(exc), "default_action": "allow"}


async def guarded_file_read(path: str) -> str:
    """Read a file with checkIntent before and reportAction after."""
    # Check intent
    if CLAWDEFENDER_AVAILABLE and claw is not None:
        try:
            intent = claw.check_intent(
                description=f"Read file: {path}",
                action_type="file_read",
                target=path,
                reason="Test server file read",
            )
            if not intent.allowed:
                return f"BLOCKED: {intent.explanation}"
        except Exception:
            pass  # fail-open

    # Perform the action
    try:
        content = Path(path).read_text()
        result_status = "success"
    except Exception as exc:
        content = f"Error: {exc}"
        result_status = "failure"

    # Report action
    if CLAWDEFENDER_AVAILABLE and claw is not None:
        try:
            claw.report_action(
                description=f"Read file: {path}",
                action_type="file_read",
                target=path,
                result=result_status,
            )
        except Exception:
            pass  # fail-open

    return content


async def guarded_shell_execute(command: str) -> str:
    """Execute a shell command with requestPermission and reportAction."""
    # Request permission
    if CLAWDEFENDER_AVAILABLE and claw is not None:
        try:
            perm = claw.request_permission(
                resource=command,
                operation="execute",
                justification=f"Test server needs to run: {command}",
            )
            if not perm.granted:
                return "PERMISSION_DENIED"
        except Exception:
            pass  # fail-open

    # Execute
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        output = proc.stdout or proc.stderr
        result_status = "success" if proc.returncode == 0 else "failure"
    except Exception as exc:
        output = f"Error: {exc}"
        result_status = "failure"

    # Report
    if CLAWDEFENDER_AVAILABLE and claw is not None:
        try:
            claw.report_action(
                description=f"Shell execute: {command}",
                action_type="shell_execute",
                target=command,
                result=result_status,
                details={"output_length": len(output)},
            )
        except Exception:
            pass  # fail-open

    return output


# ---------------------------------------------------------------------------
# Simple JSON-RPC server over stdio (MCP-like)
# ---------------------------------------------------------------------------


async def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Handle a JSON-RPC request."""
    method = request.get("method", "")
    params = request.get("params", {})
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "clawdefender-test-server-python",
                    "version": "0.5.0",
                },
            },
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Read file contents",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "run_command",
                        "description": "Run a shell command",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "command": {"type": "string"},
                            },
                            "required": ["command"],
                        },
                    },
                ]
            },
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name == "read_file":
            content = await guarded_file_read(args.get("path", ""))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": content}],
                },
            }

        if tool_name == "run_command":
            output = await guarded_shell_execute(args.get("command", ""))
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": output}],
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Unknown tool: {tool_name}",
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


async def main() -> None:
    """Run the server on stdio, reading JSON-RPC line by line."""
    # Startup policy check
    policy = await startup_policy_check()
    print(
        json.dumps({"type": "startup", "policy": policy}),
        file=sys.stderr,
    )

    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line = await reader.readline()
        if not line:
            break

        line_str = line.decode("utf-8").strip()
        if not line_str:
            continue

        try:
            request = json.loads(line_str)
        except json.JSONDecodeError:
            continue

        # Skip notifications (no id)
        if "id" not in request:
            continue

        response = await handle_request(request)
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    asyncio.run(main())
