# ClawDefender Network Architecture (Phase 12)

## High-Level Architecture

```
                          macOS System
    +----------------------------------------------------------+
    |                                                          |
    |  User Apps (Safari, etc.)                               |
    |    |                                                    |
    |    | (always pass through)                              |
    |    v                                                    |
    |  +----------------------------------------------------+ |
    |  |        Network Extension (NEFilterDataProvider)     | |
    |  |                                                    | |
    |  |  1. Is this an agent PID?                          | |
    |  |     NO  -> Allow immediately                       | |
    |  |     YES -> XPC query to daemon                     | |
    |  |                                                    | |
    |  |  DNS Proxy (NEDNSProxyProvider)                    | |
    |  |     Intercepts DNS queries from agent PIDs         | |
    |  |     Evaluates against DNS filter                   | |
    |  |     Blocks malicious domains (returns NXDOMAIN)    | |
    |  +----------------------------------------------------+ |
    |           |                    |                         |
    |           | XPC (policy query) | XPC (DNS query)        |
    |           v                    v                         |
    |  +----------------------------------------------------+ |
    |  |              ClawDefender Daemon                    | |
    |  |                                                    | |
    |  |  +----------------+  +-----------+  +----------+   | |
    |  |  | Network Policy |  | DNS       |  | Rate     |   | |
    |  |  | Engine         |  | Filter    |  | Limiter  |   | |
    |  |  +----------------+  +-----------+  +----------+   | |
    |  |         |                  |                        | |
    |  |         v                  v                        | |
    |  |  +----------------------------------------------+  | |
    |  |  | Signal Aggregation                           |  | |
    |  |  |  - IoC engine (threat intel feed)            |  | |
    |  |  |  - Behavioral engine (anomaly scoring)       |  | |
    |  |  |  - Kill chain detector (multi-step attacks)  |  | |
    |  |  |  - Guard restrictions (per-agent allowlists) |  | |
    |  |  +----------------------------------------------+  | |
    |  |         |                                          | |
    |  |         v                                          | |
    |  |  +----------------------------------------------+  | |
    |  |  | Audit Logger + Network Connection Log        |  | |
    |  |  +----------------------------------------------+  | |
    |  +----------------------------------------------------+ |
    |           |                                              |
    |           | IPC (events + status)                        |
    |           v                                              |
    |  +----------------------------------------------------+ |
    |  |              GUI (Tauri App)                        | |
    |  |  Dashboard | Network Log | Settings | Alerts       | |
    |  +----------------------------------------------------+ |
    +----------------------------------------------------------+
```

## Connection Flow

When an outbound TCP/UDP connection is initiated:

1. **Network Extension** intercepts the flow via `NEFilterDataProvider.handleNewFlow()`.
2. The extension checks if the source PID is a known agent process.
   - **Not an agent**: Allow immediately. No logging, no evaluation.
   - **Is an agent**: Continue to step 3.
3. The extension sends an XPC query to the daemon with connection metadata (PID, destination IP/domain, port, protocol).
4. The **Network Policy Engine** evaluates the connection:
   - Check IoC database for known threat indicators.
   - Check guard restrictions (per-agent allowlists).
   - Evaluate static rules (user-defined + defaults).
   - Consult behavioral engine for anomaly scoring.
   - Check kill chain detector for multi-step attack patterns.
   - Apply default action if no rule matched.
5. The decision (Allow/Block/Prompt) is returned to the extension.
6. The extension enforces the decision (`NEFilterNewFlowVerdict`).
7. The connection is logged to the audit system with full metadata.

## XPC Bridge Design

The XPC bridge connects the Network Extension (runs as a system extension in a separate sandbox) to the daemon:

```
Network Extension (sandbox)  <--XPC-->  ClawDefender Daemon
     NEFilterDataProvider                   PolicyEngine
     NEDNSProxyProvider                     DnsFilter
```

### Protocol

- **Service name**: `com.clawdefender.daemon.network`
- **Message format**: Codable structs over NSXPCConnection
- **Authentication**: Code-signing requirement (both sides must be signed by the same team)
- **Timeout**: 500ms per query (fail-open on timeout)

### Messages

| Direction | Message | Purpose |
|-----------|---------|---------|
| Ext -> Daemon | `EvaluateConnection(pid, dest, port, proto)` | Policy decision request |
| Daemon -> Ext | `ConnectionDecision(allow/block/prompt, reason)` | Policy result |
| Ext -> Daemon | `EvaluateDNS(domain, query_type, pid)` | DNS filter request |
| Daemon -> Ext | `DNSDecision(allow/block, reason)` | DNS filter result |
| Ext -> Daemon | `ReportStats(flows, blocked, allowed)` | Periodic statistics |
| Daemon -> Ext | `UpdateConfig(settings)` | Push config changes |

## DNS Proxy Architecture

The DNS proxy runs inside the Network Extension as a `NEDNSProxyProvider`:

```
Agent Process
    |
    | DNS query (port 53)
    v
NEDNSProxyProvider
    |
    +-- Allowlist check (fast path)
    |
    +-- Blocklist check (exact + wildcard)
    |
    +-- IoC domain check
    |
    +-- Domain intelligence (DGA detection, entropy)
    |
    +-- Cache lookup (recent decisions)
    |
    +-- Forward to upstream resolver (if allowed)
    |
    v
Response (or NXDOMAIN if blocked)
```

### Caching

- DNS decisions are cached per domain with configurable TTL (default: 300s).
- Cache is pruned periodically to prevent unbounded growth.
- IoC feed updates invalidate affected cache entries.

## Integration with Behavioral Engine

The behavioral engine provides anomaly scoring for network connections:

- **Server profile**: Tracks whether an MCP server has ever made network connections.
- **Destination profile**: Tracks known destinations per server.
- **Anomaly scoring**: Novel destinations from servers that rarely network get higher scores.
- **Kill chain integration**: Network connections following credential reads or file exfiltration are flagged.

### Kill Chain Patterns

The kill chain detector watches for multi-step attack sequences:

```
Step 1: Credential file read (/etc/passwd, ~/.ssh/*)
Step 2: Network connection to external host
        -> Severity: CRITICAL
        -> Action: Block (if kill chain context is active)
```

## Integration with IoC Engine

The threat intelligence feed provides:

- **Domain blocklist**: Known C2 domains.
- **IP blocklist**: Known malicious IP addresses.
- **Feed refresh**: Periodic updates from configurable sources.
- **Priority**: IoC matches override ALL other signals, including user allow rules.

## Mock Extension (Development)

For development without Apple Developer entitlements:

```
eslogger (connect events)
    |
    v
MockNetworkExtension
    |
    +-- Same evaluation logic as real extension
    |
    +-- Logs decisions but does NOT block
    |
    +-- Statistics tracked for GUI display
    |
    v
Audit Logger (same format as real extension)
```

The mock extension processes eslogger `connect` events and evaluates them against the same policy engine. It cannot actually block connections since it does not run as a system extension.
