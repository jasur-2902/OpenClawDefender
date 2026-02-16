# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in ClawAI, please report it responsibly.

**Preferred:** [GitHub private vulnerability report](https://github.com/clawai/clawai/security/advisories/new)

**Alternative:** Email [security@clawai.dev](mailto:security@clawai.dev)

Do not open a public issue for security vulnerabilities.

## Scope

The following are in scope for security reports:

- **Policy bypasses** — tool calls that should be blocked by a policy rule but are allowed through.
- **JSON-RPC parser bugs** — malformed input that causes crashes, hangs, or incorrect routing.
- **Privilege escalation** — any way ClawAI itself can be used to gain elevated access.
- **Audit log tampering** — circumventing or falsifying audit records.
- **Configuration injection** — manipulating policy files or ClawAI configuration through crafted MCP messages.

## Out of scope

- Vulnerabilities in MCP servers themselves (report those to the server maintainers).
- Vulnerabilities in MCP clients (report those to the client maintainers).
- Issues that require a pre-compromised system (ClawAI assumes the OS is not already compromised).
- Denial of service via resource exhaustion (we'll fix these, but they're low severity for a local tool).

## Response timeline

| Stage | Timeline |
|---|---|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix for critical issues | Within 7 days |
| Fix for non-critical issues | Within 30 days |
| Public disclosure | After fix is released, coordinated with reporter |

## Security design

ClawAI is designed with a defense-in-depth approach:

- Written in Rust to eliminate memory safety vulnerabilities.
- No network access required — runs entirely locally.
- Minimal dependencies, audited with `cargo-audit`.
- Policy engine is deliberately simple to reduce attack surface.
- eslogger integration is read-only observation; ClawAI never injects into other processes.
