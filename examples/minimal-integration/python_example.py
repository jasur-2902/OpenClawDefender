"""Minimal ClawDefender integration -- single checkIntent call."""

from clawdefender import ClawDefenderClient

claw = ClawDefenderClient()

# Before performing any action, check if the policy allows it.
intent = claw.check_intent_sync(
    description="Read config file",
    action_type="file_read",
    target="/etc/app/config.yaml",
)

if intent.allowed:
    print("Allowed -- proceed with file read")
else:
    print(f"Blocked: {intent.explanation}")
