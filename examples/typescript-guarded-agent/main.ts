/**
 * Example: A TypeScript agent with ClawDefender guard protection.
 *
 * This agent reads files from a workspace, processes them, and writes output.
 * The guard ensures it can ONLY access its workspace and a specific API.
 */

import { AgentGuard } from "@clawdefender/agent";
import { homedir } from "os";
import { join } from "path";

async function main(): Promise<void> {
  const workspace = join(homedir(), "Projects", "workspace");

  // Create a guard with precise permissions.
  const guard = new AgentGuard({
    name: "file-processor-bot",
    allowedPaths: [`${workspace}/**`],
    allowedTools: ["read_file", "write_file", "list_directory"],
    blockedPaths: ["~/.ssh/", "~/.aws/", "~/.config/"],
    networkAllowlist: ["api.anthropic.com"],
    shellPolicy: "deny",
  });

  // Activate the guard with fallback to embedded mode.
  await guard.activate({ fallback: true });
  console.log(`Guard activated (healthy=${guard.isHealthy()})`);

  // --- Simulate realistic agent work ---

  // 1. Read a file from the workspace (allowed).
  let result = await guard.checkAction(
    "file_read",
    join(workspace, "input.txt"),
  );
  console.log(result.allowed ? "OK: reading input.txt" : `BLOCKED: ${result.reason}`);

  // 2. Write output to the workspace (allowed).
  result = await guard.checkAction(
    "file_write",
    join(workspace, "output.txt"),
  );
  console.log(result.allowed ? "OK: writing output.txt" : `BLOCKED: ${result.reason}`);

  // 3. Try to read SSH keys (always blocked).
  result = await guard.checkAction(
    "file_read",
    join(homedir(), ".ssh", "id_rsa"),
  );
  console.log(
    result.allowed
      ? "ERROR: should have been blocked!"
      : `BLOCKED (expected): ${result.reason}`,
  );

  // 4. Try to execute a shell command (blocked by policy).
  result = await guard.checkAction("shell_execute", "rm -rf /");
  console.log(
    result.allowed
      ? "ERROR: should have been blocked!"
      : `BLOCKED (expected): ${result.reason}`,
  );

  // 5. Try to access an unauthorized API (blocked).
  result = await guard.checkAction(
    "network_request",
    "evil-server.example.com",
  );
  console.log(
    result.allowed
      ? "ERROR: should have been blocked!"
      : `BLOCKED (expected): ${result.reason}`,
  );

  // 6. Access the allowed API (allowed).
  result = await guard.checkAction("network_request", "api.anthropic.com");
  console.log(
    result.allowed
      ? "OK: accessing api.anthropic.com"
      : `BLOCKED: ${result.reason}`,
  );

  // --- Print stats ---
  const stats = guard.stats();
  console.log("\nGuard stats:");
  console.log(`  Allowed: ${stats.operationsAllowed}`);
  console.log(`  Blocked: ${stats.operationsBlocked}`);
  console.log(`  Status:  ${JSON.stringify(stats.status)}`);

  // Deactivate the guard when done.
  await guard.deactivate();
  console.log("Guard deactivated.");
}

main().catch(console.error);
