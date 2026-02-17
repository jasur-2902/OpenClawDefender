/** Minimal ClawDefender integration -- single checkIntent call. */

import { ClawDefenderClient } from "@clawdefender/sdk";

const claw = new ClawDefenderClient();

// Before performing any action, check if the policy allows it.
const intent = await claw.checkIntent({
  description: "Read config file",
  actionType: "file_read",
  target: "/etc/app/config.yaml",
});

if (intent.allowed) {
  console.log("Allowed -- proceed with file read");
} else {
  console.log(`Blocked: ${intent.explanation}`);
}
