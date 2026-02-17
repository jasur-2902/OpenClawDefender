"""Tests for async client variants."""

from __future__ import annotations

import pytest

from clawdefender.types import (
    CheckIntentResponse,
    GetPolicyResponse,
    ReportActionResponse,
    RequestPermissionResponse,
    RiskLevel,
)

from .conftest import MockConnection


@pytest.mark.asyncio
async def test_acheck_intent(claw, mock_conn: MockConnection):
    resp = await claw.acheck_intent(
        description="Read secret",
        action_type="file_read",
        target="/etc/shadow",
    )
    assert isinstance(resp, CheckIntentResponse)
    assert resp.allowed is True
    assert resp.risk_level == RiskLevel.LOW


@pytest.mark.asyncio
async def test_arequest_permission(claw, mock_conn: MockConnection):
    resp = await claw.arequest_permission(
        resource="/dev/sda",
        operation="write",
        justification="Disk image",
    )
    assert isinstance(resp, RequestPermissionResponse)
    assert resp.granted is True


@pytest.mark.asyncio
async def test_areport_action(claw, mock_conn: MockConnection):
    resp = await claw.areport_action(
        description="Deleted temp",
        action_type="file_delete",
        target="/tmp/junk",
        result="success",
    )
    assert isinstance(resp, ReportActionResponse)
    assert resp.recorded is True
    assert resp.event_id == "evt-001"


@pytest.mark.asyncio
async def test_aget_policy(claw, mock_conn: MockConnection):
    resp = await claw.aget_policy()
    assert isinstance(resp, GetPolicyResponse)
    assert resp.default_action == "allow"


@pytest.mark.asyncio
async def test_async_context_manager(mock_conn: MockConnection):
    import clawdefender

    client = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    client._conn = mock_conn

    async with client as c:
        resp = await c.acheck_intent("test", "other", "x")
        assert resp.allowed is True
