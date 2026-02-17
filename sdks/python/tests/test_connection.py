"""Tests for connection modes and fail-open behaviour."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from clawdefender.connection import (
    FailOpenConnection,
    _extract_result,
    _fail_open_response,
)
from clawdefender.exceptions import ConnectionError, ProtocolError


# ---------------------------------------------------------------------------
# _extract_result
# ---------------------------------------------------------------------------


def test_extract_result_success():
    resp = {
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": '{"allowed": true, "risk_level": "Low"}'}]
        },
        "id": 1,
    }
    data = _extract_result(resp)
    assert data["allowed"] is True


def test_extract_result_error():
    resp = {"jsonrpc": "2.0", "error": {"code": -1, "message": "bad"}, "id": 1}
    with pytest.raises(ProtocolError, match="MCP error"):
        _extract_result(resp)


def test_extract_result_malformed():
    resp = {"jsonrpc": "2.0", "result": {"content": []}, "id": 1}
    with pytest.raises(ProtocolError, match="Unexpected"):
        _extract_result(resp)


# ---------------------------------------------------------------------------
# Fail-open defaults
# ---------------------------------------------------------------------------


def test_fail_open_check_intent():
    data = _fail_open_response("checkIntent")
    assert data["allowed"] is True
    assert data["risk_level"] == "Low"


def test_fail_open_request_permission():
    data = _fail_open_response("requestPermission")
    assert data["granted"] is True


def test_fail_open_report_action():
    data = _fail_open_response("reportAction")
    assert data["recorded"] is False


def test_fail_open_get_policy():
    data = _fail_open_response("getPolicy")
    assert data["default_action"] == "allow"


# ---------------------------------------------------------------------------
# FailOpenConnection
# ---------------------------------------------------------------------------


def test_fail_open_connection_unavailable():
    """When factory raises, fail-open returns safe defaults."""

    def bad_factory():
        raise ConnectionError("no server")

    conn = FailOpenConnection(bad_factory)
    result = conn.send("checkIntent", {"description": "x", "action_type": "other", "target": "y"})
    assert result["allowed"] is True


def test_fail_open_connection_send_error():
    """When inner connection.send raises, fail-open catches it."""
    inner = MagicMock()
    inner.send.side_effect = RuntimeError("boom")
    conn = FailOpenConnection(lambda: inner)
    conn._inner = inner
    result = conn.send("requestPermission", {})
    assert result["granted"] is True


@pytest.mark.asyncio
async def test_fail_open_connection_async_unavailable():
    def bad_factory():
        raise ConnectionError("no server")

    conn = FailOpenConnection(bad_factory)
    result = await conn.asend("checkIntent", {})
    assert result["allowed"] is True
