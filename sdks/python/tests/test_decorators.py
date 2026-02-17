"""Tests for @requires_permission and @reports_action decorators."""

from __future__ import annotations

import pytest

import clawdefender
from clawdefender import PermissionDenied, reports_action, requires_permission

from .conftest import DENIED_PERMISSION, MockConnection


# ---------------------------------------------------------------------------
# @requires_permission
# ---------------------------------------------------------------------------


def test_requires_permission_sync_allowed(claw, mock_conn: MockConnection):
    @requires_permission(operation="write", justification="test write", client=claw)
    def write_file(path: str, content: str) -> str:
        return "ok"

    result = write_file("/tmp/test.txt", "hello")
    assert result == "ok"
    assert mock_conn.calls[-1][0] == "requestPermission"
    assert mock_conn.calls[-1][1]["resource"] == "/tmp/test.txt"


def test_requires_permission_sync_denied(mock_conn: MockConnection):
    mock_conn._overrides["requestPermission"] = DENIED_PERMISSION
    claw = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    claw._conn = mock_conn
    clawdefender._default_client = claw

    @requires_permission(operation="execute", justification="run cmd", client=claw)
    def run_command(command: str) -> str:
        return "should not reach"

    with pytest.raises(PermissionDenied) as exc_info:
        run_command("rm -rf /")
    assert "rm -rf /" in str(exc_info.value)


@pytest.mark.asyncio
async def test_requires_permission_async_allowed(claw, mock_conn: MockConnection):
    @requires_permission(operation="read", justification="read file", client=claw)
    async def read_file(path: str) -> str:
        return "contents"

    result = await read_file("/etc/passwd")
    assert result == "contents"
    assert mock_conn.calls[-1][0] == "requestPermission"


@pytest.mark.asyncio
async def test_requires_permission_async_denied(mock_conn: MockConnection):
    mock_conn._overrides["requestPermission"] = DENIED_PERMISSION
    claw = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    claw._conn = mock_conn

    @requires_permission(operation="execute", client=claw)
    async def run(command: str) -> str:
        return "no"

    with pytest.raises(PermissionDenied):
        await run("bad-cmd")


def test_requires_permission_target_param(claw, mock_conn: MockConnection):
    @requires_permission(
        operation="connect", target_param="endpoint", client=claw
    )
    def connect(endpoint: str, timeout: int = 5) -> str:
        return "connected"

    connect("https://api.example.com")
    assert mock_conn.calls[-1][1]["resource"] == "https://api.example.com"


# ---------------------------------------------------------------------------
# @reports_action
# ---------------------------------------------------------------------------


def test_reports_action_sync_success(claw, mock_conn: MockConnection):
    @reports_action(action_type="file_write", client=claw)
    def save(path: str, data: str) -> None:
        pass

    save("/tmp/out.txt", "data")
    assert mock_conn.calls[-1][0] == "reportAction"
    assert mock_conn.calls[-1][1]["result"] == "success"


def test_reports_action_sync_failure(claw, mock_conn: MockConnection):
    @reports_action(action_type="file_write", client=claw)
    def save(path: str) -> None:
        raise RuntimeError("disk full")

    with pytest.raises(RuntimeError):
        save("/tmp/out.txt")
    assert mock_conn.calls[-1][0] == "reportAction"
    assert mock_conn.calls[-1][1]["result"] == "failure"


@pytest.mark.asyncio
async def test_reports_action_async_success(claw, mock_conn: MockConnection):
    @reports_action(action_type="network_request", client=claw)
    async def fetch(url: str) -> str:
        return "<html>"

    result = await fetch("https://example.com")
    assert result == "<html>"
    assert mock_conn.calls[-1][0] == "reportAction"
    assert mock_conn.calls[-1][1]["result"] == "success"


@pytest.mark.asyncio
async def test_reports_action_async_failure(claw, mock_conn: MockConnection):
    @reports_action(action_type="network_request", client=claw)
    async def fetch(url: str) -> str:
        raise IOError("timeout")

    with pytest.raises(IOError):
        await fetch("https://example.com")
    assert mock_conn.calls[-1][1]["result"] == "failure"
