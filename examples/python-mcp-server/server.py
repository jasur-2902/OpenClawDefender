"""
Example MCP server with full ClawDefender Level 3 integration.

This server exposes file-operation tools (read, write, list) and demonstrates
every ClawDefender security checkpoint:

  1. checkIntent   -- before performing any action
  2. requestPermission -- before writes and other sensitive operations
  3. reportAction  -- after every action completes

Run with:
    python server.py
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# ── ClawDefender SDK ─────────────────────────────────────────────────────────
# If ClawDefender is not running, the SDK falls back to allow-all so the
# server can still function without the firewall installed.
try:
    from clawdefender import ClawDefenderClient
    from clawdefender.exceptions import PermissionDenied

    claw = ClawDefenderClient()
    CLAWDEFENDER_AVAILABLE = True
except ImportError:
    claw = None  # type: ignore[assignment]
    CLAWDEFENDER_AVAILABLE = False

    class PermissionDenied(Exception):  # type: ignore[no-redef]
        pass


app = Server("example-file-operations")


# ── Tool definitions ─────────────────────────────────────────────────────────


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="read_file",
            description="Read the contents of a file",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"},
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="write_file",
            description="Write content to a file",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write"},
                    "content": {"type": "string", "description": "Content to write"},
                },
                "required": ["path", "content"],
            },
        ),
        Tool(
            name="list_directory",
            description="List files in a directory",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path"},
                },
                "required": ["path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "read_file":
        return await _read_file(arguments["path"])
    elif name == "write_file":
        return await _write_file(arguments["path"], arguments["content"])
    elif name == "list_directory":
        return await _list_directory(arguments["path"])
    else:
        raise ValueError(f"Unknown tool: {name}")


# ── Tool implementations with ClawDefender checkpoints ───────────────────────


async def _read_file(path: str) -> list[TextContent]:
    """Read a file. Demonstrates checkIntent + reportAction."""

    # CHECKPOINT 1: Check intent before doing anything.
    if CLAWDEFENDER_AVAILABLE:
        intent = await claw.check_intent(
            description=f"Read file: {path}",
            action_type="file_read",
            target=path,
            reason="User requested file contents",
        )
        if not intent.allowed:
            return [TextContent(type="text", text=f"Blocked by policy: {intent.explanation}")]

    # Perform the action.
    try:
        content = Path(path).read_text()
        result = "success"
    except Exception as exc:
        content = f"Error reading file: {exc}"
        result = "failure"

    # CHECKPOINT 3: Report what happened.
    if CLAWDEFENDER_AVAILABLE:
        await claw.report_action(
            description=f"Read file: {path}",
            action_type="file_read",
            target=path,
            result=result,
        )

    return [TextContent(type="text", text=content)]


async def _write_file(path: str, content: str) -> list[TextContent]:
    """Write a file. Demonstrates checkIntent + requestPermission + reportAction."""

    # CHECKPOINT 1: Check intent.
    if CLAWDEFENDER_AVAILABLE:
        intent = await claw.check_intent(
            description=f"Write file: {path}",
            action_type="file_write",
            target=path,
            reason="User requested file write",
        )
        if not intent.allowed:
            return [TextContent(type="text", text=f"Blocked by policy: {intent.explanation}")]

    # CHECKPOINT 2: Request explicit permission for write operations.
    if CLAWDEFENDER_AVAILABLE:
        try:
            perm = await claw.request_permission(
                resource=path,
                operation="write",
                justification=f"Writing {len(content)} bytes to {path}",
            )
            if not perm.granted:
                return [TextContent(type="text", text="Permission denied by user")]
        except PermissionDenied as exc:
            return [TextContent(type="text", text=f"Permission denied: {exc}")]

    # Perform the action.
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        Path(path).write_text(content)
        result = "success"
        msg = f"Wrote {len(content)} bytes to {path}"
    except Exception as exc:
        result = "failure"
        msg = f"Error writing file: {exc}"

    # CHECKPOINT 3: Report the outcome.
    if CLAWDEFENDER_AVAILABLE:
        await claw.report_action(
            description=f"Write file: {path}",
            action_type="file_write",
            target=path,
            result=result,
        )

    return [TextContent(type="text", text=msg)]


async def _list_directory(path: str) -> list[TextContent]:
    """List directory contents. Demonstrates checkIntent + reportAction."""

    if CLAWDEFENDER_AVAILABLE:
        intent = await claw.check_intent(
            description=f"List directory: {path}",
            action_type="file_read",
            target=path,
            reason="User requested directory listing",
        )
        if not intent.allowed:
            return [TextContent(type="text", text=f"Blocked by policy: {intent.explanation}")]

    try:
        entries = sorted(os.listdir(path))
        content = "\n".join(entries)
        result = "success"
    except Exception as exc:
        content = f"Error listing directory: {exc}"
        result = "failure"

    if CLAWDEFENDER_AVAILABLE:
        await claw.report_action(
            description=f"List directory: {path}",
            action_type="file_read",
            target=path,
            result=result,
        )

    return [TextContent(type="text", text=content)]


# ── Entry point ──────────────────────────────────────────────────────────────


def main():
    asyncio.run(_run())


async def _run():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    main()
