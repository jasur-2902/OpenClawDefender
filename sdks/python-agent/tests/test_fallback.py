"""Tests for embedded fallback enforcement."""

from __future__ import annotations

import os

import pytest

from clawdefender.agent.fallback import EmbeddedEnforcer
from clawdefender.agent.types import ActionVerdict


class TestPathEnforcement:
    """Tests for path-based enforcement."""

    def test_allowed_path_glob(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_paths=["/tmp/*"])
        enforcer.activate()
        result = enforcer.check_action("file_read", "/tmp/test.txt")
        assert result.allowed is True

    def test_blocked_path_not_in_allowed(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_paths=["/tmp/*"])
        enforcer.activate()
        result = enforcer.check_action("file_write", "/etc/passwd")
        assert result.allowed is False
        assert result.verdict == ActionVerdict.BLOCK

    def test_blocked_paths_take_priority(self):
        enforcer = EmbeddedEnforcer(
            name="test",
            allowed_paths=["/tmp/*"],
            blocked_paths=["/tmp/secret/*"],
        )
        enforcer.activate()
        result = enforcer.check_action("file_read", "/tmp/secret/key.pem")
        assert result.allowed is False

    def test_no_allowed_paths_means_allow_all(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_paths=None)
        enforcer.activate()
        result = enforcer.check_action("file_read", "/any/path/file.txt")
        assert result.allowed is True

    def test_path_prefix_matching(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_paths=["/home/user/project"])
        enforcer.activate()
        result = enforcer.check_action("file_read", "/home/user/project/src/main.py")
        assert result.allowed is True


class TestShellEnforcement:
    """Tests for shell policy enforcement."""

    def test_shell_deny(self):
        enforcer = EmbeddedEnforcer(name="test", shell_policy="deny")
        enforcer.activate()
        result = enforcer.check_action("shell_execute", "ls -la")
        assert result.allowed is False

    def test_shell_allowlist_allowed(self):
        enforcer = EmbeddedEnforcer(
            name="test",
            shell_policy="allowlist",
            allowed_commands=["ls", "cat", "grep"],
        )
        enforcer.activate()
        result = enforcer.check_action("shell_execute", "ls -la /tmp")
        assert result.allowed is True

    def test_shell_allowlist_blocked(self):
        enforcer = EmbeddedEnforcer(
            name="test",
            shell_policy="allowlist",
            allowed_commands=["ls"],
        )
        enforcer.activate()
        result = enforcer.check_action("shell_execute", "rm -rf /")
        assert result.allowed is False


class TestNetworkEnforcement:
    """Tests for network allowlist enforcement."""

    def test_network_no_allowlist_allows_all(self):
        enforcer = EmbeddedEnforcer(name="test", network_allowlist=None)
        enforcer.activate()
        result = enforcer.check_action("network_request", "https://example.com")
        assert result.allowed is True

    def test_network_allowlist_match(self):
        enforcer = EmbeddedEnforcer(name="test", network_allowlist=["https://api.example.com/*"])
        enforcer.activate()
        result = enforcer.check_action("network_request", "https://api.example.com/v1/data")
        assert result.allowed is True

    def test_network_allowlist_no_match(self):
        enforcer = EmbeddedEnforcer(name="test", network_allowlist=["https://api.example.com/*"])
        enforcer.activate()
        result = enforcer.check_action("network_request", "https://evil.com/steal")
        assert result.allowed is False


class TestToolEnforcement:
    """Tests for tool allowlist enforcement."""

    def test_tool_no_allowlist_allows_all(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_tools=None)
        enforcer.activate()
        result = enforcer.check_action("tool_use", "any_tool")
        assert result.allowed is True

    def test_tool_in_allowlist(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_tools=["read_file", "write_file"])
        enforcer.activate()
        result = enforcer.check_action("tool_use", "read_file")
        assert result.allowed is True

    def test_tool_not_in_allowlist(self):
        enforcer = EmbeddedEnforcer(name="test", allowed_tools=["read_file"])
        enforcer.activate()
        result = enforcer.check_action("tool_use", "execute_code")
        assert result.allowed is False


class TestRateLimiting:
    """Tests for rate limiting."""

    def test_file_rate_limit(self):
        enforcer = EmbeddedEnforcer(name="test", max_files_per_minute=2)
        enforcer.activate()
        r1 = enforcer.check_action("file_read", "/tmp/a.txt")
        r2 = enforcer.check_action("file_read", "/tmp/b.txt")
        r3 = enforcer.check_action("file_read", "/tmp/c.txt")
        assert r1.allowed is True
        assert r2.allowed is True
        assert r3.allowed is False
        assert "rate limit" in r3.reason.lower()


class TestStats:
    """Tests for enforcer statistics."""

    def test_stats_counting(self):
        enforcer = EmbeddedEnforcer(name="stat-test", allowed_paths=["/tmp/*"])
        enforcer.activate()
        enforcer.check_action("file_read", "/tmp/ok.txt")
        enforcer.check_action("file_read", "/etc/blocked")
        s = enforcer.stats()
        assert s.allowed_count == 1
        assert s.blocked_count == 1
        assert s.checked_count == 2
        assert s.name == "stat-test"
