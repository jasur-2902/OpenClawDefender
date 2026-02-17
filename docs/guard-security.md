# Guard Security Model

This document describes the security properties, trust model, and limitations
of the ClawDefender Agent Guard system.

## Trust Model

The Agent Guard is a **self-imposed restriction**, not a jail. The agent
voluntarily restricts itself by declaring what resources it needs and then
activating a guard that enforces those declarations. This is analogous to
a program calling `pledge()` or `unveil()` on OpenBSD — the process opts in
to a restricted sandbox.

Key principles:

- **Voluntary adoption.** The agent or its framework activates the guard.
  Nothing prevents the agent from not activating a guard at all.
- **Honest declaration.** The guard trusts the agent to declare truthful
  permissions at activation time. After activation, those permissions are
  enforced.
- **Defense in depth.** The guard is one layer in a multi-layer security
  architecture. It should be combined with external monitoring, audit
  logging, and human oversight.

## What the Guard CAN Prevent

When the guard is active (in Enforce mode), it blocks:

- **File access outside declared paths.** Any `file_read`, `file_write`, or
  `file_delete` operation on paths not matching the declared glob patterns
  is blocked.
- **Access to sensitive paths.** Paths matching `~/.ssh/**`, `~/.aws/**`,
  `~/.gnupg/**`, `~/.config/gcloud/**`, `.env`, `.git/config`, `id_rsa`,
  and `id_ed25519` are always blocked regardless of declared permissions.
- **Undeclared tool usage.** If the guard has a tool allowlist, any tool
  not in the list is blocked.
- **Network access to undeclared hosts.** Network requests to hosts not
  in the allowlist are blocked.
- **Shell execution when denied.** The default shell policy is `deny`.
  Shell commands are blocked unless the policy is set to `allowlist` with
  specific commands permitted.

## What the Guard CANNOT Prevent

The guard operates at the MCP (Model Context Protocol) layer. It cannot
prevent:

- **Direct syscalls bypassing MCP.** If a process makes direct system calls
  (e.g., via `open()`, `connect()`) without going through the MCP tool
  interface, the guard cannot intercept them. This applies to the embedded
  fallback mode. The daemon mode can provide OS-level enforcement via
  eBPF/seccomp on supported platforms.
- **Actions by untracked processes.** The guard only monitors operations
  routed through the guard's `check_action` interface. Child processes,
  background jobs, or other processes on the system are not monitored.
- **Attacks on the guard infrastructure itself.** If an attacker can modify
  the guard binary, the daemon socket, or the token file, they can disable
  or bypass the guard.
- **Data exfiltration via allowed channels.** If the agent is allowed to
  access a network host, it can send arbitrary data to that host. The guard
  does not inspect payload contents.

## Fallback Mode Limitations

When the ClawDefender daemon is unavailable, the guard falls back to
embedded in-process enforcement. This mode has additional limitations:

- **No OS-level monitoring.** The embedded enforcer only checks operations
  that are explicitly routed through `check_action()`. It cannot monitor
  file system activity, network connections, or process execution at the
  OS level.
- **No behavioral analysis.** The embedded mode does not track patterns
  of behavior over time. It only checks individual operations against
  static rules.
- **MCP-level enforcement only.** The embedded mode relies on the AI
  framework (e.g., Claude Code, LangChain) to route all tool calls
  through the guard. If the framework does not do this, operations
  are invisible to the guard.
- **No inter-guard coordination.** In embedded mode, each guard instance
  is independent. There is no central registry to detect conflicting
  permissions or coordinate across agents.

The embedded mode honestly reports its limitations. It does not claim
OS-level monitoring capability. The guard status will be `Active` (not
"Full OS Enforcement") and log messages explicitly state "embedded mode."

## Multi-Guard Isolation

The guard registry supports multiple simultaneous guards with independent
permissions and statistics:

- **Path isolation.** Guard A with access to `~/workspace-a/` cannot read
  or write files in `~/workspace-b/`, and vice versa.
- **Independent stats.** Each guard tracks its own `checks_total`,
  `checks_allowed`, and `checks_blocked` counters independently.
- **Independent tool lists.** Each guard has its own tool allowlist.
  Guard A having access to `execute_shell` does not grant Guard B the
  same access.
- **Sensitive path override.** The global sensitive path blocklist applies
  to ALL guards regardless of their individual permissions.

## Tamper-Proofing

**Can an agent bypass its own guard?** Yes. The guard is voluntary and
the agent could:

1. Simply not activate a guard.
2. Deactivate the guard before performing restricted operations.
3. Make direct system calls without going through `check_action()`.
4. Kill the daemon process.

This is by design. The guard is a **trust signal**, not a security boundary.
It allows agents to demonstrate good intent by self-restricting, and allows
frameworks and operators to verify that agents are operating within declared
bounds.

**Recommendations for external enforcement:**

- Use the daemon mode with OS-level enforcement (eBPF/seccomp) for stronger
  guarantees.
- Monitor guard deactivation events in audit logs and alert on unexpected
  deactivation.
- Run agents in sandboxed environments (containers, VMs) where the guard
  adds an additional layer but is not the sole protection.
- Use health checks to verify the guard is still active during long-running
  operations.

## Privilege Escalation Attack Surface

### REST API

The guard management API listens on `127.0.0.1:3202` (localhost only) and
requires Bearer token authentication. Attack vectors:

- **Missing or weak token.** If the token is empty or predictable, any
  local process can create, modify, or delete guards. Mitigation: the
  token is stored in `~/.local/share/clawdefender/server-token` with
  restrictive file permissions.
- **Token timing attacks.** The API uses constant-time comparison for
  token validation to prevent timing-based token extraction.
- **Local privilege escalation.** Any process running as the same user
  can read the token file. Mitigation: this is a same-user boundary,
  not a privilege boundary. The guard does not claim cross-user isolation.

### IPC Protocol

The daemon communicates via Unix domain socket at
`/tmp/clawdefender-daemon.sock`. Attack vectors:

- **Socket hijacking.** If an attacker can create the socket before the
  daemon, they can intercept guard registrations. Mitigation: the daemon
  should verify socket ownership and permissions at startup.
- **PID spoofing.** The registry tracks guard PIDs for cleanup but does
  not authenticate PID ownership at registration time. A malicious process
  could register a guard with another process's PID. Mitigation:
  `cleanup_dead_pids()` removes guards with non-running PIDs, limiting
  the window for abuse.

### Guard Deregistration

Any client with a valid guard ID can deregister that guard. Guard IDs are
UUIDs and are not predictable, but they are returned to the registering
client and could be leaked via logs or IPC.

## Recommendations

### Production Use

- Use **Enforce mode** in production. Monitor mode is for development and
  permission discovery only.
- Enable **health checks** to detect guard deactivation or daemon
  disconnection.
- Do not disable the guard in error handlers. If an operation fails, the
  guard should remain active.
- Monitor **audit logs** for guard deactivation events and unexpected
  blocked operations.

### Development Use

- Use **Monitor mode** to discover required permissions without blocking
  operations.
- Use `suggest_permissions()` to generate a minimal permission set from
  monitored operations.
- Run the daemon in development to test full integration before deploying
  to production.

### General

- Keep the ClawDefender daemon and guard library up to date.
- Review and minimize declared permissions regularly.
- Combine the guard with external sandboxing (containers, VMs, seccomp
  profiles) for defense in depth.
- Do not store sensitive data in paths accessible to agents.
- Use separate guard instances for separate agents with distinct permission
  requirements.
