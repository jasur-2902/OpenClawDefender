"""Monitor mode — record operations and suggest minimal permissions."""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from typing import Optional

from .types import MonitorRecord, PermissionConfig

logger = logging.getLogger("clawdefender.agent")


class MonitorLog:
    """Records operations and analyzes them to suggest permissions."""

    def __init__(self) -> None:
        self._records: list[MonitorRecord] = []

    def record(
        self,
        action: str,
        target: str,
        would_block: bool,
        reason: str = "",
    ) -> MonitorRecord:
        entry = MonitorRecord(
            timestamp=time.time(),
            action=action,
            target=target,
            would_block=would_block,
            reason=reason,
        )
        self._records.append(entry)
        return entry

    @property
    def records(self) -> list[MonitorRecord]:
        return list(self._records)

    @property
    def total_count(self) -> int:
        return len(self._records)

    @property
    def would_block_count(self) -> int:
        return sum(1 for r in self._records if r.would_block)

    def clear(self) -> None:
        self._records.clear()

    def suggest_permissions(self) -> dict:
        """Analyze recorded operations and return a suggested permission config.

        Groups file operations by common directory prefixes and network targets
        to produce a minimal permission set that would allow all observed operations.
        """
        paths: set[str] = set()
        tools: set[str] = set()
        network_targets: set[str] = set()
        commands: set[str] = set()
        has_shell = False
        has_network = False

        file_actions = {"file_read", "file_write", "file_delete"}

        for rec in self._records:
            if rec.action in file_actions:
                resolved = os.path.abspath(rec.target)
                paths.add(resolved)
            elif rec.action == "tool_use":
                tools.add(rec.target)
            elif rec.action == "network_request":
                has_network = True
                network_targets.add(rec.target)
            elif rec.action == "shell_execute":
                has_shell = True
                cmd_name = rec.target.split()[0] if rec.target.strip() else rec.target
                commands.add(cmd_name)

        config = PermissionConfig()

        # Group paths by common directory prefixes
        if paths:
            config.allowed_paths = _collapse_paths(paths)

        if tools:
            config.allowed_tools = sorted(tools)

        if has_network and network_targets:
            config.network_allowlist = sorted(network_targets)

        if has_shell:
            config.shell_policy = "allowlist"
            config.allowed_commands = sorted(commands)
        else:
            config.shell_policy = "deny"

        result = config.to_dict()
        result["_summary"] = {
            "total_operations": self.total_count,
            "would_have_blocked": self.would_block_count,
            "unique_paths": len(paths),
            "unique_tools": len(tools),
            "unique_network_targets": len(network_targets),
        }
        return result


def _collapse_paths(paths: set[str]) -> list[str]:
    """Collapse a set of file paths into directory-level patterns.

    Groups files that share a common directory and produces glob patterns
    like ``/home/user/project/*`` instead of listing every file.
    """
    dir_counts: dict[str, int] = defaultdict(int)
    for p in paths:
        dir_counts[os.path.dirname(p)] += 1

    result: list[str] = []
    covered: set[str] = set()

    for directory, count in sorted(dir_counts.items(), key=lambda x: -x[1]):
        if any(directory.startswith(c) for c in covered):
            continue
        if count >= 3:
            result.append(os.path.join(directory, "*"))
            covered.add(directory)
        else:
            for p in paths:
                if os.path.dirname(p) == directory and p not in covered:
                    result.append(p)
                    covered.add(p)

    return sorted(result)
