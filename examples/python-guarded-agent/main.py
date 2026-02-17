"""Example: A Python agent with ClawDefender guard protection.

This agent reads files from a workspace, processes them, and writes output.
The guard ensures it can ONLY access its workspace and a specific API.
"""

import os
import sys

from clawdefender.agent import AgentGuard


def main() -> None:
    # Define the workspace this agent operates in.
    workspace = os.path.expanduser("~/Projects/workspace/")

    # Create a guard with precise permissions.
    guard = AgentGuard(
        name="file-processor-bot",
        allowed_paths=[f"{workspace}**"],
        allowed_tools=["read_file", "write_file", "list_directory"],
        blocked_paths=["~/.ssh/", "~/.aws/", "~/.config/"],
        network_allowlist=["api.anthropic.com"],
        shell_policy="deny",
    )

    # Activate the guard. If the ClawDefender daemon is running, it connects
    # to it for full OS-level enforcement. Otherwise, it falls back to
    # in-process enforcement.
    guard.activate(fallback=True)
    print(f"Guard '{guard.name}' activated (healthy={guard.is_healthy()})")

    # --- Simulate realistic agent work ---

    # 1. Read a file from the workspace (allowed).
    result = guard.check_action("file_read", f"{workspace}input.txt")
    if result.allowed:
        print(f"OK: reading {workspace}input.txt")
    else:
        print(f"BLOCKED: {result.reason}")

    # 2. Write output to the workspace (allowed).
    result = guard.check_action("file_write", f"{workspace}output.txt")
    if result.allowed:
        print(f"OK: writing {workspace}output.txt")
    else:
        print(f"BLOCKED: {result.reason}")

    # 3. Try to read SSH keys (always blocked).
    result = guard.check_action("file_read", os.path.expanduser("~/.ssh/id_rsa"))
    if result.allowed:
        print("ERROR: should have been blocked!")
    else:
        print(f"BLOCKED (expected): {result.reason}")

    # 4. Try to execute a shell command (blocked by policy).
    result = guard.check_action("shell_execute", "rm -rf /")
    if result.allowed:
        print("ERROR: should have been blocked!")
    else:
        print(f"BLOCKED (expected): {result.reason}")

    # 5. Try to access an unauthorized API (blocked).
    result = guard.check_action("network_request", "evil-server.example.com")
    if result.allowed:
        print("ERROR: should have been blocked!")
    else:
        print(f"BLOCKED (expected): {result.reason}")

    # 6. Access the allowed API (allowed).
    result = guard.check_action("network_request", "api.anthropic.com")
    if result.allowed:
        print("OK: accessing api.anthropic.com")
    else:
        print(f"BLOCKED: {result.reason}")

    # --- Print stats ---

    stats = guard.stats()
    print(f"\nGuard stats:")
    print(f"  Allowed: {stats.allowed_count}")
    print(f"  Blocked: {stats.blocked_count}")
    print(f"  Total:   {stats.checked_count}")
    print(f"  Uptime:  {stats.uptime_seconds:.1f}s")

    # Deactivate the guard when done.
    guard.deactivate()
    print("Guard deactivated.")


if __name__ == "__main__":
    main()
