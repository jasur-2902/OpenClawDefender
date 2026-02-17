"""Example: OpenClaw bot with ClawDefender guard integration.

This demonstrates how to protect an OpenClaw bot with the AgentGuard.
Each permission choice is explained with comments.
"""

import os

from clawdefender.agent import AgentGuard


def create_openclaw_guard() -> AgentGuard:
    """Create a guard tailored for an OpenClaw bot.

    OpenClaw bots typically need:
    - Read access to their project directory for context
    - Write access to their output directory
    - Network access to the LLM API they use
    - No shell access (bots should not run arbitrary commands)
    """
    project_dir = os.path.expanduser("~/openclaw-project/")

    guard = AgentGuard(
        # Unique name for this bot instance. Used in logs and the daemon registry.
        name="openclaw-assistant-bot",

        # ALLOWED PATHS: Only the project directory and a scratch area.
        # Use glob patterns. "**" matches any depth of subdirectories.
        allowed_paths=[
            f"{project_dir}**",       # The project the bot works on
            "/tmp/openclaw-scratch/",  # Temporary scratch space for processing
        ],

        # ALLOWED TOOLS: Restrict which MCP tools the bot can invoke.
        # Only list the tools this specific bot actually needs.
        allowed_tools=[
            "read_file",
            "write_file",
            "list_directory",
            "search_files",
        ],

        # BLOCKED PATHS: Sensitive directories that must never be accessed,
        # even if they fall inside an allowed path pattern.
        # ClawDefender always blocks ~/.ssh and ~/.aws by default, but
        # listing them explicitly documents the intent.
        blocked_paths=[
            "~/.ssh/",
            "~/.aws/",
            "~/.config/",
            "~/.gnupg/",
            "/etc/",
        ],

        # NETWORK ALLOWLIST: Only the LLM provider API.
        # The bot has no reason to contact any other host.
        network_allowlist=["api.anthropic.com"],

        # SHELL POLICY: "deny" blocks all shell/command execution.
        # An OpenClaw bot should never need to run shell commands.
        shell_policy="deny",

        # MODE: Start in "monitor" during development to discover what
        # the bot actually needs. Switch to "enforce" for production.
        mode="monitor",
    )

    return guard


def main() -> None:
    guard = create_openclaw_guard()

    # --- Development workflow ---
    # Step 1: Activate in monitor mode to observe the bot's behavior.
    guard.activate(fallback=True)
    print(f"Guard '{guard.name}' activated in monitor mode")

    # Step 2: Run the bot's normal workload.
    # In monitor mode, nothing is blocked, but everything is logged.
    guard.check_action("file_read", os.path.expanduser("~/openclaw-project/README.md"))
    guard.check_action("file_write", os.path.expanduser("~/openclaw-project/output/result.md"))
    guard.check_action("network_request", "api.anthropic.com")

    # Simulate an unexpected operation the bot might try:
    guard.check_action("shell_execute", "curl http://example.com")

    # Step 3: After observing, check what the bot actually tried to do.
    suggestions = guard.suggest_permissions()
    print(f"\nPermission suggestions based on observed behavior:")
    for key, values in suggestions.items():
        if values:
            print(f"  {key}: {values}")

    # Step 4: Review stats.
    stats = guard.stats()
    print(f"\nMonitor stats:")
    print(f"  Total checks: {stats.checked_count}")
    print(f"  Would-block:  {stats.blocked_count}")

    # Step 5: Once satisfied, switch to enforce mode in production.
    # Just change mode="enforce" in the constructor above.

    guard.deactivate()
    print("\nGuard deactivated. Review suggestions above, then switch to enforce mode.")


if __name__ == "__main__":
    main()
