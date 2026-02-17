"""Tests for AgentGuard class."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from clawdefender.agent.guard import AgentGuard
from clawdefender.agent.exceptions import (
    GuardActivationError,
    GuardNotActiveError,
)
from clawdefender.agent.types import ActionVerdict, GuardStats


class TestGuardActivation:
    """Tests for guard activation and deactivation."""

    def test_activate_fallback_embedded(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        assert guard.active is True
        assert guard._embedded is True
        guard.deactivate()

    def test_activate_without_fallback_raises(self):
        guard = AgentGuard(name="test")
        with pytest.raises(GuardActivationError):
            guard.activate(fallback=False)

    def test_deactivate(self):
        guard = AgentGuard(name="test")
        guard.activate(fallback=True)
        guard.deactivate()
        assert guard.active is False

    def test_double_activate_is_noop(self):
        guard = AgentGuard(name="test")
        guard.activate(fallback=True)
        guard.activate(fallback=True)  # should not raise
        assert guard.active is True
        guard.deactivate()

    def test_deactivate_inactive_is_noop(self):
        guard = AgentGuard(name="test")
        guard.deactivate()  # should not raise

    def test_context_manager_sync(self):
        with AgentGuard(name="test") as guard:
            assert guard.active is True
        assert guard.active is False

    @pytest.mark.asyncio
    async def test_context_manager_async(self):
        async with AgentGuard(name="test") as guard:
            assert guard.active is True
        assert guard.active is False

    def test_del_deactivates(self):
        guard = AgentGuard(name="test")
        guard.activate(fallback=True)
        assert guard.active is True
        guard.__del__()
        assert guard.active is False


class TestGuardCheckAction:
    """Tests for check_action method."""

    def test_check_raises_when_not_active(self):
        guard = AgentGuard(name="test")
        with pytest.raises(GuardNotActiveError):
            guard.check_action("file_read", "/tmp/test.txt")

    def test_check_allowed_path(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        result = guard.check_action("file_read", "/tmp/test.txt")
        assert result.allowed is True
        guard.deactivate()

    def test_check_blocked_path(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        result = guard.check_action("file_read", "/etc/passwd")
        assert result.allowed is False
        assert result.verdict == ActionVerdict.BLOCK
        guard.deactivate()

    def test_check_shell_denied(self):
        guard = AgentGuard(name="test", shell_policy="deny")
        guard.activate(fallback=True)
        result = guard.check_action("shell_execute", "rm -rf /")
        assert result.allowed is False
        guard.deactivate()

    def test_check_shell_allowlist(self):
        guard = AgentGuard(name="test", shell_policy="allowlist", allowed_commands=["ls", "cat"])
        guard.activate(fallback=True)
        result_ls = guard.check_action("shell_execute", "ls -la")
        result_rm = guard.check_action("shell_execute", "rm -rf /")
        assert result_ls.allowed is True
        assert result_rm.allowed is False
        guard.deactivate()

    def test_check_bool_conversion(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        result = guard.check_action("file_read", "/tmp/test.txt")
        assert bool(result) is True
        result2 = guard.check_action("file_read", "/etc/passwd")
        assert bool(result2) is False
        guard.deactivate()


class TestGuardStats:
    """Tests for guard statistics."""

    def test_stats_raises_when_not_active(self):
        guard = AgentGuard(name="test")
        with pytest.raises(GuardNotActiveError):
            guard.stats()

    def test_stats_basic(self):
        guard = AgentGuard(name="test-stats", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        guard.check_action("file_read", "/tmp/test.txt")
        guard.check_action("file_read", "/etc/passwd")
        s = guard.stats()
        assert isinstance(s, GuardStats)
        assert s.name == "test-stats"
        assert s.active is True
        assert s.allowed_count == 1
        assert s.blocked_count == 1
        assert s.checked_count == 2
        assert s.uptime_seconds >= 0
        guard.deactivate()

    def test_allowed_count_property(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        guard.check_action("file_read", "/tmp/a.txt")
        guard.check_action("file_read", "/tmp/b.txt")
        assert guard.allowed_count == 2
        guard.deactivate()

    def test_blocked_count_property(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"])
        guard.activate(fallback=True)
        guard.check_action("file_read", "/etc/a")
        assert guard.blocked_count == 1
        guard.deactivate()


class TestGuardHealth:
    """Tests for health check."""

    def test_not_healthy_when_inactive(self):
        guard = AgentGuard(name="test")
        assert guard.is_healthy() is False

    def test_healthy_when_active_embedded(self):
        guard = AgentGuard(name="test")
        guard.activate(fallback=True)
        assert guard.is_healthy() is True
        guard.deactivate()

    def test_not_healthy_after_deactivate(self):
        guard = AgentGuard(name="test")
        guard.activate(fallback=True)
        guard.deactivate()
        assert guard.is_healthy() is False


class TestGuardMonitorMode:
    """Tests for monitor mode integration."""

    def test_monitor_mode_allows_everything(self):
        guard = AgentGuard(name="test", allowed_paths=["/tmp/*"], mode="monitor")
        guard.activate(fallback=True)
        result = guard.check_action("file_read", "/etc/passwd")
        # Monitor mode always allows
        assert result.allowed is True
        assert "[monitor]" in result.reason
        guard.deactivate()

    def test_suggest_permissions_in_monitor_mode(self):
        guard = AgentGuard(name="test", mode="monitor")
        guard.activate(fallback=True)
        guard.check_action("file_read", "/tmp/a.txt")
        guard.check_action("shell_execute", "ls")
        perms = guard.suggest_permissions()
        assert "_summary" in perms
        assert perms["_summary"]["total_operations"] == 2
        guard.deactivate()

    def test_suggest_permissions_not_monitor(self):
        guard = AgentGuard(name="test", mode="enforce")
        guard.activate(fallback=True)
        result = guard.suggest_permissions()
        assert "error" in result
        guard.deactivate()
