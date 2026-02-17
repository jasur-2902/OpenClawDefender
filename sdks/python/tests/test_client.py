"""Tests for the core ClawDefender client methods."""

from __future__ import annotations

from clawdefender.types import (
    CheckIntentResponse,
    GetPolicyResponse,
    PermissionScope,
    ReportActionResponse,
    RequestPermissionResponse,
    RiskLevel,
)

from .conftest import MockConnection


def test_check_intent(claw, mock_conn: MockConnection):
    resp = claw.check_intent(
        description="Read config file",
        action_type="file_read",
        target="/etc/config.yml",
    )
    assert isinstance(resp, CheckIntentResponse)
    assert resp.allowed is True
    assert resp.risk_level == RiskLevel.LOW
    assert resp.explanation == "Action is safe"
    assert mock_conn.calls[-1][0] == "checkIntent"


def test_check_intent_with_reason(claw, mock_conn: MockConnection):
    claw.check_intent(
        description="Read config",
        action_type="file_read",
        target="/etc/config.yml",
        reason="Needed for setup",
    )
    _, params = mock_conn.calls[-1]
    assert params["reason"] == "Needed for setup"


def test_request_permission(claw, mock_conn: MockConnection):
    resp = claw.request_permission(
        resource="/tmp/output.txt",
        operation="write",
        justification="Writing build output",
    )
    assert isinstance(resp, RequestPermissionResponse)
    assert resp.granted is True
    assert resp.scope == PermissionScope.SESSION


def test_report_action(claw, mock_conn: MockConnection):
    resp = claw.report_action(
        description="Wrote output",
        action_type="file_write",
        target="/tmp/output.txt",
        result="success",
    )
    assert isinstance(resp, ReportActionResponse)
    assert resp.recorded is True
    assert resp.event_id == "evt-001"


def test_report_action_with_details(claw, mock_conn: MockConnection):
    claw.report_action(
        description="Wrote output",
        action_type="file_write",
        target="/tmp/output.txt",
        result="success",
        details={"bytes": 1024},
    )
    _, params = mock_conn.calls[-1]
    assert params["details"] == {"bytes": 1024}


def test_get_policy(claw, mock_conn: MockConnection):
    resp = claw.get_policy(resource="/tmp/*")
    assert isinstance(resp, GetPolicyResponse)
    assert len(resp.rules) == 1
    assert resp.default_action == "allow"


def test_get_policy_filters(claw, mock_conn: MockConnection):
    claw.get_policy(action_type="file_write", tool_name="write_file")
    _, params = mock_conn.calls[-1]
    assert params["action_type"] == "file_write"
    assert params["tool_name"] == "write_file"


def test_client_context_manager(mock_conn: MockConnection):
    import clawdefender

    client = clawdefender.ClawDefender.__new__(clawdefender.ClawDefender)
    client._conn = mock_conn
    with client as c:
        c.check_intent("test", "other", "x")
    # After exiting, close should have been called (no error)
