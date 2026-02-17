"""Tests for monitor mode and suggest_permissions."""

from __future__ import annotations

import pytest

from clawdefender.agent.monitor import MonitorLog, _collapse_paths


class TestMonitorLog:
    """Tests for the MonitorLog class."""

    def test_record_operation(self):
        log = MonitorLog()
        rec = log.record("file_read", "/tmp/test.txt", would_block=False)
        assert rec.action == "file_read"
        assert rec.target == "/tmp/test.txt"
        assert rec.would_block is False
        assert log.total_count == 1

    def test_would_block_count(self):
        log = MonitorLog()
        log.record("file_read", "/tmp/a.txt", would_block=False)
        log.record("file_read", "/etc/passwd", would_block=True)
        log.record("shell_execute", "rm -rf /", would_block=True)
        assert log.would_block_count == 2
        assert log.total_count == 3

    def test_clear(self):
        log = MonitorLog()
        log.record("file_read", "/tmp/a.txt", would_block=False)
        log.clear()
        assert log.total_count == 0

    def test_records_returns_copy(self):
        log = MonitorLog()
        log.record("file_read", "/tmp/a.txt", would_block=False)
        records = log.records
        assert len(records) == 1
        records.clear()
        assert log.total_count == 1  # original not affected


class TestSuggestPermissions:
    """Tests for the suggest_permissions analysis."""

    def test_suggest_from_file_ops(self):
        log = MonitorLog()
        log.record("file_read", "/tmp/workspace/a.txt", would_block=False)
        log.record("file_read", "/tmp/workspace/b.txt", would_block=False)
        log.record("file_write", "/tmp/workspace/c.txt", would_block=False)
        result = log.suggest_permissions()
        assert "allowed_paths" in result
        assert result["_summary"]["total_operations"] == 3

    def test_suggest_from_shell_ops(self):
        log = MonitorLog()
        log.record("shell_execute", "ls -la", would_block=True)
        log.record("shell_execute", "cat file.txt", would_block=True)
        result = log.suggest_permissions()
        assert result["shell_policy"] == "allowlist"
        assert "ls" in result["allowed_commands"]
        assert "cat" in result["allowed_commands"]

    def test_suggest_from_network_ops(self):
        log = MonitorLog()
        log.record("network_request", "https://api.example.com/data", would_block=True)
        result = log.suggest_permissions()
        assert "network_allowlist" in result
        assert "https://api.example.com/data" in result["network_allowlist"]

    def test_suggest_from_tool_ops(self):
        log = MonitorLog()
        log.record("tool_use", "read_file", would_block=False)
        log.record("tool_use", "write_file", would_block=False)
        result = log.suggest_permissions()
        assert "allowed_tools" in result
        assert "read_file" in result["allowed_tools"]

    def test_suggest_empty_log(self):
        log = MonitorLog()
        result = log.suggest_permissions()
        assert result["shell_policy"] == "deny"
        assert result["_summary"]["total_operations"] == 0


class TestCollapsePaths:
    """Tests for path collapsing utility."""

    def test_collapse_many_in_same_dir(self):
        paths = {"/tmp/work/a.txt", "/tmp/work/b.txt", "/tmp/work/c.txt"}
        result = _collapse_paths(paths)
        assert any("/tmp/work/*" in p for p in result)

    def test_collapse_few_in_same_dir(self):
        paths = {"/tmp/a.txt", "/home/user/b.txt"}
        result = _collapse_paths(paths)
        # Only 1 file per dir, should list individually
        assert len(result) == 2
