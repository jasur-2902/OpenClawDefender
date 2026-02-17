"""Minimal ClawDefender guard example (5 lines)."""

from clawdefender.agent import AgentGuard

guard = AgentGuard(name="my-bot", allowed_paths=["~/workspace/"], shell_policy="deny")
guard.activate(fallback=True)
# ... your agent code here ...
guard.deactivate()
