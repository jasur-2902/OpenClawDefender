/** Minimal ClawDefender guard example. */

import { AgentGuard } from "@clawdefender/agent";

const guard = new AgentGuard({ name: "my-bot", allowedPaths: ["~/workspace/"], shellPolicy: "deny" });
await guard.activate({ fallback: true });
// ... your agent code here ...
await guard.deactivate();
