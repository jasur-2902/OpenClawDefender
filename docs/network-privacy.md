# ClawDefender Network Extension: Privacy & Security Design

This document describes what the ClawDefender Network Extension can and cannot see, how it filters traffic, and how user privacy is protected.

## What the Network Extension CAN See

The extension operates at the network metadata level only:

- **Connection metadata**: source/destination IP addresses, ports, and transport protocol (TCP/UDP)
- **DNS queries**: domain names being resolved (A, AAAA, CNAME, etc.)
- **Byte counts**: total bytes sent and received per connection (volume only, not content)
- **Process information**: PID, process name, and whether the process is a registered MCP agent
- **TLS indicator**: whether TLS was negotiated (boolean flag only)

## What the Network Extension CANNOT See

- **Encrypted content**: ClawDefender does NOT perform TLS interception, MITM proxying, or certificate injection. The contents of HTTPS connections are never decrypted or inspected.
- **HTTP request/response bodies**: even for plaintext HTTP, the extension does not read or store payload data. Only metadata (IP, port, domain, byte count) is logged.
- **User credentials**: passwords, tokens, cookies, and authentication headers are never extracted or stored.
- **Application-layer data**: the extension does not parse HTTP headers, WebSocket frames, gRPC messages, or any other application protocol beyond DNS.

## Filtering Scope: Agent Processes Only

The Network Extension applies filtering ONLY to registered AI agent processes (MCP servers managed by ClawDefender). All other traffic is unconditionally allowed:

- **Non-agent processes**: user browsers, email clients, system services, and all other applications are NEVER filtered, inspected, or logged.
- **Agent identification**: a process is considered an agent only if it is registered with the ClawDefender daemon as a running MCP server. Unknown processes default to non-agent (allowed).
- **Localhost traffic**: connections to 127.0.0.1, ::1, and `localhost` are always allowed for all processes, including agents.

## Fail-Open Design

ClawDefender is designed to fail open — if any component is unavailable, all network connections are allowed:

- **Daemon unavailable**: if the ClawDefender daemon is not running or unreachable, the Network Extension allows all connections. The `DaemonBridge.permissiveOnDisconnect` flag defaults to `true`.
- **No blocklist loaded**: if the DNS filter has no blocklist entries, all DNS queries are allowed.
- **Policy engine errors**: non-agent traffic is always allowed regardless of engine state. Agent traffic defaults to the configured action (prompt by default), never silent block.
- **XPC communication failure**: if XPC calls to the daemon fail, the extension falls back to allow.

This design ensures that ClawDefender never degrades the user's network connectivity, even during failures.

## User Control

- **Disable anytime**: the Network Extension can be disabled at any time in macOS System Settings > Network > Filters, or from the ClawDefender GUI settings.
- **Per-rule control**: users can add allow/block rules for specific domains, IPs, or CIDR ranges through the GUI or CLI.
- **Guard restrictions**: when Guard mode is active, only destinations in the allowlist are permitted for agent processes. This provides maximum restriction when needed.

## Data Storage

- **Local only**: all network connection logs, DNS query logs, and traffic statistics are stored locally on the user's machine.
- **No cloud sync**: network data is never uploaded to any cloud service or third-party server.
- **Log retention**: logs follow the user's configured retention policy and can be cleared at any time.

## Telemetry

- **Opt-in only**: network data is never included in telemetry unless the user explicitly enables telemetry.
- **Aggregated counts only**: even when telemetry is opted in, only aggregated counts are sent (e.g., "42 connections blocked today"), never individual connection details, domains, or IP addresses.
- **No PII**: telemetry never includes process names, server names, domain names, IP addresses, or any other personally identifiable information.

## Threat Model

| Component | What It Protects Against | Failure Mode |
|---|---|---|
| Network Policy Engine | Malicious agent connections to C2 servers, data exfiltration | Fail-open: allow all |
| DNS Filter | DNS-based C2, DGA domains, known malicious domains | Fail-open: allow all |
| IoC Feed | Known threat indicators (IPs, domains) | No feed = no blocking |
| Guard Mode | Agent exceeding its declared network scope | No guard = default policy |
| Rate Limiter | Connection flooding, scanning behavior | Alerts only, never blocks |

## Design Principles

1. **Metadata only**: never inspect encrypted content or application payloads.
2. **Agent-scoped**: never filter, log, or inspect non-agent user traffic.
3. **Fail-open**: network failures must never break the user's connectivity.
4. **User in control**: the user can always disable, override, or customize filtering.
5. **Local storage**: no network data leaves the machine without explicit opt-in.
