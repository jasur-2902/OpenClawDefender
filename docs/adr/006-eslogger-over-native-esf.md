# ADR-006: eslogger Over Native Endpoint Security Framework

**Status:** Accepted

## Context

ClawDefender needs OS-level visibility into what AI agents actually do on the system — file reads, process execution, network connections — to correlate with declared MCP tool calls and detect discrepancies.

On macOS, Apple provides two paths to kernel-level event monitoring:

1. **Endpoint Security Framework (ESF)** — a native C API that provides both AUTH (blocking) and NOTIFY (observation) event types. Requires a special entitlement (`com.apple.developer.endpoint-security.client`) that Apple grants only after a review process.

2. **eslogger** — a command-line tool that ships with macOS (since Ventura). It wraps ESF internally, is already entitled by Apple, and outputs events as JSON to stdout. It supports only NOTIFY events.

## Decision

ClawDefender uses `eslogger` for OS-level monitoring rather than the native Endpoint Security Framework.

### Rationale

**The Apple entitlement is the critical blocker.** Native ESF requires `com.apple.developer.endpoint-security.client`. Obtaining this entitlement requires:
- An Apple Developer account ($99/year)
- A formal application to Apple explaining the use case
- A review process that takes weeks to months with no guaranteed approval
- The entitlement is tied to a specific Developer ID and binary signing identity

This means: **open-source contributors cannot build and run ClawDefender with native ESF.** They would need *our* signing identity or their own approved entitlement. This fundamentally conflicts with open-source development. Contributors could not test the monitoring code they're modifying.

**eslogger ships with macOS and is already entitled.** Every Mac running Ventura or later has `eslogger` at `/usr/bin/eslogger`. Apple has already granted it the ESF entitlement. Any user can run it (with appropriate TCC permissions). No signing, no entitlement application, no waiting.

**Same event stream, different format.** `eslogger` exposes the same kernel events as native ESF — process execution, file access, network connections, etc. The only difference is the delivery format (JSON on stdout vs. C callbacks) and the event mode (NOTIFY only, no AUTH).

**NOTIFY-only is acceptable because MCP proxy handles blocking.** The MCP proxy layer is where ClawDefender enforces policy decisions (allow/deny/prompt). The OS monitoring layer exists for *visibility and correlation* — detecting whether what happened at the OS level matches what was declared at the MCP level. For this purpose, observation (NOTIFY) is sufficient. We don't need to block OS events because we've already blocked the unauthorized MCP call that would have triggered them.

### Trade-off: cannot block at OS level

With native ESF AUTH events, ClawDefender could block a file read *at the kernel level* even if the MCP proxy was bypassed. With eslogger, if something bypasses the MCP proxy (e.g., an agent spawns a subprocess that acts independently), ClawDefender can only *detect and log* the activity, not prevent it.

This is documented as a known limitation in the README and threat model.

### Future: native ESF as optional enhancement

If Apple approves an ESF entitlement for ClawDefender, we will add native ESF support as an optional, additive layer:

- `eslogger` remains the default (works for everyone, no special setup)
- Native ESF becomes an opt-in mode for users who install the signed binary
- Native ESF adds AUTH capability — blocking at the OS level for defense in depth
- The `clawdefender-monitor` crate is designed with this migration path in mind (trait-based event source abstraction)

## Consequences

- ClawDefender's OS monitoring works out of the box on macOS Ventura+ with no special setup beyond TCC permissions.
- Open-source contributors can build, test, and modify the monitoring code without any Apple entitlement.
- OS-level enforcement is observation-only. Blocking happens at the MCP proxy layer.
- `eslogger` JSON parsing must handle format changes across macOS versions. We pin to known schema versions and handle unknown fields gracefully.
- Spawning and managing an `eslogger` child process adds complexity (startup, crash recovery, log rotation).
