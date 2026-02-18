# ClawDefender v0.3 Release Notes — Phase 12: Network Protection

## Summary

Phase 12 adds **network-level prevention** to ClawDefender. Previous phases provided detection and monitoring of AI agent behavior. Phase 12 extends this to actively control outbound network connections from agent processes, including DNS filtering and connection blocking.

## What's New

### Prevention vs Detection

ClawDefender now operates in two modes:

- **Detection** (Phases 0-11): Monitor agent behavior, log events, generate alerts.
- **Prevention** (Phase 12): Actively block malicious outbound connections before data leaves the machine.

### macOS Network Extension

A new macOS Network Extension (`NEFilterDataProvider` + `NEDNSProxyProvider`) intercepts outbound connections from agent processes:

- Evaluates each connection against the network policy engine.
- Blocks connections to known threat indicators (IoC feed).
- Filters DNS queries to prevent C2 domain resolution.
- Non-agent (user) traffic is never filtered or inspected.

### Network Policy Engine

Multi-signal evaluation engine for outbound connections:

- **IoC matching**: Blocks connections to known malicious infrastructure (highest priority).
- **Guard restrictions**: Per-agent network allowlists from guard policies.
- **Static rules**: User-defined allow/block rules with wildcard and CIDR support.
- **Behavioral signals**: Anomaly scoring based on server network profiles.
- **Kill chain integration**: Escalates severity when network connections follow suspicious activity.
- **Rate limiting**: Alerts on connection bursts (configurable thresholds).

### DNS Filter

Domain-level filtering engine:

- Exact and wildcard blocklists.
- IoC domain feed integration.
- Domain intelligence (DGA detection, entropy analysis).
- Allowlist overrides for user-trusted domains.
- Fail-open design: unknown domains are allowed by default.

### Connection Logging

Full forensic logging for every evaluated connection:

- Metadata only (no content inspection, no TLS decryption).
- Per-server traffic statistics.
- Summary aggregation for dashboard display.
- Filterable by action, protocol, server, destination.

### GUI Updates

- **Dashboard**: New network activity card showing allowed/blocked/prompted counts.
- **Network Log**: Full connection log with filtering and search.
- **Settings**: Network configuration page (filter enable/disable, default action, DNS options).
- **Sidebar**: Network section in navigation.

### CLI Commands

```bash
clawdefender network status    # Show extension and filter status
clawdefender network log       # View recent connection log
clawdefender network allow     # Add domain to allowlist
clawdefender network block     # Add domain to blocklist
clawdefender network rules     # List active network rules
```

## Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `filter_enabled` | `true` | Enable network connection filtering |
| `dns_enabled` | `true` | Enable DNS query filtering |
| `default_action` | `prompt` | Action for unmatched agent connections |
| `prompt_timeout` | `30` | Seconds before prompt times out (then blocks) |
| `block_private_ranges` | `false` | Block connections to private IP ranges |
| `block_doh` | `false` | Block DNS-over-HTTPS to prevent DNS filter bypass |
| `log_dns` | `true` | Log DNS query decisions |
| `max_connections_per_minute` | `100` | Rate limit threshold per PID |
| `max_unique_destinations_per_10s` | `10` | Unique destination threshold per PID |

## Known Limitations

1. **Apple Developer entitlements required**: The real Network Extension requires a signed app with `com.apple.developer.networking.networkextension` entitlement. Without it, use mock mode for development.

2. **Mock mode cannot block**: The mock network extension logs decisions but cannot actually prevent connections. It is intended for development and testing only.

3. **IP-based C2 bypasses DNS filter**: If an agent connects directly by IP address, the DNS filter is not consulted. The network policy engine's IoC matching handles this case.

4. **No TLS inspection**: ClawDefender never decrypts or inspects TLS traffic. Connection decisions are based on metadata only (destination IP, port, domain, process identity).

5. **System Extension sandbox**: The Network Extension runs in a sandboxed process and communicates with the daemon via XPC. If the daemon is unavailable, the extension fails open (allows all connections).

## Migration Notes

### Upgrading from v0.2 (Phase 0-11)

- All Phase 0-11 functionality is preserved. Network protection is additive.
- The network policy engine is disabled by default until the network extension is enabled in System Settings.
- Existing guard policies are respected: per-agent network allowlists from guard configurations are enforced by the network policy engine.
- No configuration migration is required. New settings use sensible defaults.
- The daemon accepts the new `--mock-network-extension` flag for development without the real extension.

### Build changes

New justfile recipes:

```bash
just build-extension   # Build the Swift network extension
just build-all         # Build workspace + extension
just test-network      # Run all network-related tests
```
