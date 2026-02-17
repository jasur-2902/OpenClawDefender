"""Tests for the GuardedAction context manager."""

from __future__ import annotations

import pytest

from clawdefender.types import RiskLevel

from .conftest import BLOCKED_INTENT, MockConnection


# ---------------------------------------------------------------------------
# Sync context manager
# ---------------------------------------------------------------------------


def test_guarded_action_allowed(claw, mock_conn: MockConnection):
    with claw.guarded_action(
        description="Write config",
        action_type="file_write",
        target="/etc/app.conf",
    ) as guard:
        assert guard.allowed is True
        assert guard.risk_level == RiskLevel.LOW

    # Should have called checkIntent + reportAction
    methods = [m for m, _ in mock_conn.calls]
    assert "checkIntent" in methods
    assert "reportAction" in methods


def test_guarded_action_blocked(mock_conn: MockConnection):
    mock_conn._overrides["checkIntent"] = BLOCKED_INTENT
    import clawdefender

    claw = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    claw._conn = mock_conn

    with claw.guarded_action(
        description="Run shell",
        action_type="shell_execute",
        target="rm -rf /",
    ) as guard:
        assert guard.allowed is False
        assert "blocked" in guard.explanation.lower()

    # reportAction should NOT be called since action was blocked
    methods = [m for m, _ in mock_conn.calls]
    assert "reportAction" not in methods


def test_guarded_action_exception(claw, mock_conn: MockConnection):
    with pytest.raises(ValueError):
        with claw.guarded_action(
            description="Risky op",
            action_type="other",
            target="x",
        ) as guard:
            raise ValueError("boom")

    # Should still report — with failure
    report_calls = [(m, p) for m, p in mock_conn.calls if m == "reportAction"]
    assert len(report_calls) == 1
    assert report_calls[0][1]["result"] == "failure"


def test_guarded_action_explicit_report(claw, mock_conn: MockConnection):
    with claw.guarded_action(
        description="Deploy",
        action_type="network_request",
        target="https://prod.example.com",
    ) as guard:
        if guard.allowed:
            guard.report_success(details={"status": 200})

    # Explicit report should prevent auto-report in __exit__
    report_calls = [(m, p) for m, p in mock_conn.calls if m == "reportAction"]
    assert len(report_calls) == 1
    assert report_calls[0][1]["result"] == "success"


# ---------------------------------------------------------------------------
# Async context manager
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guarded_action_async_allowed(claw, mock_conn: MockConnection):
    async with claw.guarded_action(
        description="Fetch data",
        action_type="network_request",
        target="https://api.example.com/data",
    ) as guard:
        assert guard.allowed is True

    methods = [m for m, _ in mock_conn.calls]
    assert "checkIntent" in methods
    assert "reportAction" in methods


@pytest.mark.asyncio
async def test_guarded_action_async_blocked(mock_conn: MockConnection):
    mock_conn._overrides["checkIntent"] = BLOCKED_INTENT
    import clawdefender

    claw = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    claw._conn = mock_conn

    async with claw.guarded_action(
        description="Shell",
        action_type="shell_execute",
        target="bad",
    ) as guard:
        assert guard.allowed is False

    methods = [m for m, _ in mock_conn.calls]
    assert "reportAction" not in methods
