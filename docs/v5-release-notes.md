# ClawDefender v0.5.0 Release Notes

## Agentic Trust Layer

v0.5.0 introduces the **Agentic Trust Layer** -- a fundamental shift from purely adversarial monitoring to cooperative security participation. MCP servers can now voluntarily declare intent, request permission, and report actions through the ClawDefender MCP server and SDKs.

## What's New

### ClawDefender MCP Server

A new MCP server (`clawdefender-mcp-server`) that other MCP servers can call to participate in security monitoring. Exposes four tools:

- **checkIntent** -- pre-flight policy check before performing sensitive operations
- **requestPermission** -- request explicit approval for resource access
- **reportAction** -- post-action audit logging for completed operations
- **getPolicy** -- query current policy rules for planning

The MCP server runs on both stdio and HTTP transports with rate limiting, input validation, and authentication.

### Python SDK (`clawdefender-sdk`)

A Python SDK for MCP server authors to integrate ClawDefender:

- Sync and async APIs (`check_intent`, `acheck_intent`, etc.)
- `@clawdefender.guard` decorator for automatic intent checking
- `GuardedAction` context manager for check-perform-report workflows
- Graceful degradation when ClawDefender is unavailable (fail-open by default)
- Input validation (string length, null bytes, Unicode bidi control)
- Auto-detection of connection mode (stdio/HTTP)

Install: `pip install clawdefender-sdk`

### TypeScript SDK (`@clawdefender/sdk`)

A TypeScript SDK with the same feature set:

- `ClawDefender` client with `checkIntent`, `requestPermission`, `reportAction`, `getPolicy`
- Express/Koa middleware for automatic request guarding
- `guardedAction` wrapper for check-perform-report workflows
- Zod schema validation for all responses
- Fail-open connection with graceful degradation

Install: `npm install @clawdefender/sdk`

### Certification Program

A compliance certification tool (`clawdefender certify`) that tests MCP servers against three levels:

- **Level 1 (Basic Transparency)**: Server has a `clawdefender.toml` manifest declaring permissions
- **Level 2 (Active Participation)**: Server calls `checkIntent` and `reportAction`
- **Level 3 (Full Compliance)**: Server calls all four tools including `requestPermission`, and correctly stops when intent is denied

Generates JSON and human-readable reports.

### Policy Templates

Pre-built policy templates for common use cases:

- `development` -- permissive policy for local development
- `strict` -- restrictive policy for production environments
- `audit-only` -- log everything, block nothing (observation mode)
- `data-science` -- balanced policy for data analysis workflows

Manage with `clawdefender policy template list` and `clawdefender policy template apply <name>`.

### Policy Suggest

New `clawdefender policy suggest` command analyzes audit logs and recommends policy rules based on observed patterns.

### Integration Guides

Comprehensive guides for integrating ClawDefender into MCP servers:

- `docs/mcp-server-author-guide.md` -- step-by-step integration tutorial
- `docs/sdk-security.md` -- SDK security model and best practices
- `docs/integrations/` -- framework-specific integration guides

### Example Servers

Complete example MCP servers demonstrating SDK integration:

- `examples/python-mcp-server/` -- Python server with Level 3 compliance
- `examples/typescript-mcp-server/` -- TypeScript server with Level 3 compliance
- `examples/minimal-integration/` -- Minimal integration example

## New CLI Commands

| Command | Description |
|---------|-------------|
| `clawdefender serve` | Start the ClawDefender MCP server (stdio or HTTP) |
| `clawdefender certify <path>` | Run certification tests against an MCP server |
| `clawdefender policy template list` | List available policy templates |
| `clawdefender policy template apply <name>` | Apply a policy template |
| `clawdefender policy suggest` | Generate policy suggestions from audit log |

## Upgrade Instructions from v0.4.0

1. **Update binary**: `cargo install clawdefender` or rebuild from source
2. **Policy files**: No changes required. Existing policies continue to work
3. **Optional**: Add SDK integration to your MCP servers for cooperative security
4. **Optional**: Run `clawdefender policy template apply development` to start with a template

The v0.5.0 release is fully backward compatible with v0.4.0. No breaking changes.

## Architecture

The MCP server adds a third event source to the correlation engine:

```
Source 1: Proxy Interception (blocking)
Source 2: SDK Self-Reporting (cooperative)
Source 3: OS Sensor (observation)
```

All three feed into the correlation engine, which can now detect discrepancies between what an agent declares (SDK), what MCP traffic shows (proxy), and what actually happens at the OS level (sensor).

## Security Considerations

- SDK trust model: SDK reports are treated as advisory. The proxy and OS sensor remain the ground truth
- MCP server rate limiting: checkIntent (100/min), requestPermission (10/min), reportAction (1000/min)
- Input validation: string length limits, null byte rejection, Unicode bidi control detection
- HTTP authentication: Bearer token support for HTTP transport
- Scope escalation prevention: wildcards rejected in `requestPermission` resource paths

## Test Coverage

833 tests across all crates, including:
- MCP server protocol integration tests (22 tests)
- SDK flow integration tests (14 tests)
- Performance benchmarks (5 tests)
- Security hardening tests (20 tests)
- Certification harness tests (20 tests)
