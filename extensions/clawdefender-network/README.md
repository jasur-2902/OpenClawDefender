# ClawDefender Network Extension

macOS System Extension that hosts a Network Extension content filter and DNS proxy for ClawDefender. It intercepts network flows from AI agent processes and applies network policy (allow/block/prompt).

## Architecture

The extension consists of three NEProvider subclasses:

- **FilterDataProvider** -- Hot path. Intercepts every TCP/UDP flow, identifies the source PID via audit token, checks if it's an agent process, and applies network policy.
- **FilterControlProvider** -- Handles flows escalated to "prompt" mode. Requests user permission via the daemon with a 30-second timeout (defaults to block).
- **DNSProxyProvider** -- Intercepts DNS queries from agent processes. Blocked domains get NXDOMAIN responses; allowed domains are forwarded to the system resolver.

Supporting modules:

- **ProcessResolver** -- Converts `audit_token_t` to PID, caches agent-status lookups with 1-second TTL.
- **DaemonBridge** -- XPC/Unix socket IPC to the ClawDefender daemon with automatic reconnection (5s retry). Fail-open when daemon is unavailable.
- **PolicyEvaluator** -- Local fast-path evaluation: always-allow localhost, always-block IoC hosts, cache daemon decisions with 30s TTL.
- **FlowLogger** -- Structured logging via `os_log` and forwarding to daemon for audit records.

## Requirements

### Apple Developer Entitlements

This extension requires specific entitlements that can only be obtained from Apple:

- `com.apple.developer.networking.networkextension` with `content-filter-provider`, `dns-proxy`, and their `-systemextension` variants
- `com.apple.developer.system-extension.install`

These entitlements require an Apple Developer account and must be provisioned through Xcode.

### System Requirements

- macOS 13.0 (Ventura) or later
- The containing app must request System Extension activation
- User must approve the extension in System Preferences > Privacy & Security

## Building

### With Xcode (production)

1. Open the project in Xcode
2. Configure signing with your Apple Developer team
3. Add the entitlements to your provisioning profile
4. Build as part of the containing app bundle

### With Swift Package Manager (development)

```bash
cd extensions/clawdefender-network
swift build
```

Note: SPM builds will compile the code but the resulting binary cannot be used as a real system extension without proper code signing and entitlements.

## Mock Mode

For development without Apple entitlements, run in mock mode:

```bash
swift run ClawDefenderNetwork --mock
```

This starts an interactive session where you can enter JSON flow events:

```json
{"pid": 1234, "host": "api.openai.com", "port": 443}
{"pid": 5678, "host": "evil.example.com", "port": 80}
```

The mock mode queries the ClawDefender daemon via the same IPC protocol and logs decisions, but cannot actually intercept real network traffic.

### Rust-Side Mock

The daemon also includes a `--mock-network-extension` flag that simulates extension behavior using eslogger `connect` events. This is useful for end-to-end testing of the network policy pipeline without the actual macOS system extension.

## IPC Protocol

The extension communicates with the ClawDefender daemon via XPC using the `ClawDefenderNetworkProtocol`:

- `isAgentProcess(pid) -> (Bool, String?)` -- Check if a PID is an agent process
- `evaluateNetworkPolicy(pid, host, port) -> (String, String?)` -- Get policy decision
- `reportNetworkFlow(pid, host, port, action, bytes)` -- Report a flow for audit
- `requestNetworkPermission(pid, host, port, serverName) -> String` -- Request user prompt

## Flow Decision Path

```
New flow arrives
    |
    v
Extract PID from audit token
    |
    v
Is agent process? --[no]--> ALLOW (immediate, zero overhead)
    |
    [yes]
    v
Localhost? --[yes]--> ALLOW
    |
    [no]
    v
On IoC blocklist? --[yes]--> BLOCK
    |
    [no]
    v
In policy cache? --[yes]--> cached decision
    |
    [no]
    v
Query daemon for policy
    |
    +--> ALLOW
    +--> BLOCK
    +--> PROMPT --> User decision (30s timeout, default BLOCK)
```
