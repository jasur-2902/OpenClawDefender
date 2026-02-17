# Phase 9 Release Notes — Agent Self-Protection

## Summary

Phase 9 introduces the **Agent Self-Protection API**, enabling AI agents to declare and enforce their own security boundaries. This is a new capability layer that sits between the agent code and the ClawDefender daemon.

## New features

### AgentGuard (Rust core)

- `AgentGuard` struct with builder pattern for constructing guards
- `PermissionSet` with file read/write/delete patterns, shell policy, network policy, and tool allowlists
- Two enforcement modes: **Enforce** (block disallowed operations) and **Monitor** (log but allow)
- `suggest_permissions()` for discovering minimal required permissions from monitor-mode observations
- `FallbackEngine` for in-process enforcement when the daemon is unavailable
- Self-test on activation to verify enforcement is working
- TOML policy generation from `PermissionSet`
- Guard lifecycle: activate, check, deactivate, with Drop-based cleanup

### Python package (`clawdefender-agent`)

- `AgentGuard` class with daemon and embedded enforcement
- `@restricted` decorator for wrapping functions with guard protection
- `@sandboxed` decorator for zero-access isolation with timeout
- Context manager support (sync and async)
- `suggest_permissions()` for monitor-mode analysis
- `GuardStats`, `CheckResult`, and `ActionVerdict` types

### TypeScript package (`@clawdefender/agent`)

- `AgentGuard` class with daemon and fallback enforcement
- `withGuard()` and `sandboxed()` wrapper functions
- `guardMiddleware()` for MCP server integration
- `AsyncDisposable` support (`await using`)
- `FallbackEnforcer` with Node.js `fs` and `child_process` hooks
- `Monitor` class with `suggestPermissions()`

### REST API

- Full CRUD for guards: create, list, get, delete
- Action checking: `POST /guards/:id/check`
- Statistics: `GET /guards/:id/stats`
- Permission suggestions: `GET /guards/:id/suggest`
- Webhook registration for blocked-operation notifications
- Bearer token authentication
- OpenAPI 3.0 specification

### Auto-installation

- Automatic daemon detection and installation
- Consent modes: auto, prompt, manual
- Version management with semantic versioning
- Platform-specific binary resolution (macOS, Linux)

### Daemon integration

- Guard registry in the daemon with IPC protocol
- `claw guard list`, `claw guard stats`, `claw guard audit` CLI commands
- Dead-PID cleanup for guards whose agents have exited
- Guard events forwarded to the daemon event system

## Breaking changes

None. Phase 9 is additive — all existing functionality continues to work unchanged.

## Migration

No migration is needed. The Agent Self-Protection API is a new feature set with no impact on existing ClawDefender users. Agents that do not use the guard API are unaffected.

## Test coverage

- 20+ Rust integration tests covering guard lifecycle, policy generation, enforcement, monitor mode, and statistics
- Existing 1,428 Rust tests continue to pass
- 74 Python tests continue to pass
- Performance targets: guard activation < 100ms, per-check < 0.5ms
