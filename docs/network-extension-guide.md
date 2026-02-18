# ClawDefender Network Extension Guide

## What Network Protection Does

ClawDefender's network extension provides **prevention** (blocking) for outbound connections from AI agent processes, in addition to the existing detection capabilities from Phases 0-11.

- **Prevention**: Connections from agent processes are evaluated in real-time. Malicious or unauthorized connections are blocked before data leaves the machine.
- **Detection**: All connection decisions (allow, block, prompt) are logged for forensic analysis.

Non-agent (user) traffic is **never filtered, inspected, or blocked**. This is enforced at the first step of every evaluation path.

## How to Enable It

### Real Network Extension (requires Apple Developer entitlements)

1. Open **System Settings > General > Login Items & Extensions > Network Extensions**.
2. Enable **ClawDefender Network Filter**.
3. macOS will prompt you to allow the extension. Click **Allow**.
4. The extension status will appear in the ClawDefender GUI under **Settings > Network**.

### Mock Mode (development and testing)

If you do not have Apple Developer entitlements (required to sign the Network Extension), use mock mode:

```bash
clawdefender-daemon --mock-network-extension
```

Mock mode intercepts eslogger `connect` events and logs what the real extension **would** have done. It cannot actually block connections.

## Understanding the Network Log

The **Network Log** page in the GUI shows every evaluated connection:

| Column          | Description                                    |
|-----------------|------------------------------------------------|
| Timestamp       | When the connection was evaluated               |
| Server          | MCP server name (agent identity)               |
| Destination     | Domain or IP address and port                  |
| Protocol        | TCP or UDP                                     |
| Action          | Allowed, Blocked, or Prompted                  |
| Reason          | Why the decision was made (rule name, IoC, etc)|
| Bytes Sent/Recv | Traffic volume                                 |

### Filtering the log

- Filter by action (allowed/blocked/prompted)
- Filter by protocol (tcp/udp)
- Search by server name, destination, or reason text

## Configuring Network Rules

Network rules are evaluated in priority order (lower number = higher priority):

1. **IoC matches** (highest priority) -- always block known threat indicators
2. **Guard restrictions** -- enforce per-agent allowlists
3. **Static rules** -- user-defined and default rules
4. **Behavioral signals** -- anomaly-based escalation
5. **Kill chain context** -- severity escalation
6. **Default action** -- prompt, block, or allow (configurable)

### Adding rules via CLI

```bash
# Block a specific domain for agents
clawdefender network block evil-domain.com

# Allow a specific domain
clawdefender network allow api.trusted-service.com

# View current rules
clawdefender network rules
```

### Settings page

In the GUI, navigate to **Settings > Network** to configure:

- Enable/disable network filtering
- Enable/disable DNS filtering
- Default action for unknown destinations
- Block private IP ranges
- Block DNS-over-HTTPS (to prevent DNS filter bypass)

## Mock Mode for Development

Mock mode is designed for developers who want to test network policy without a real system extension:

- Start the daemon with `--mock-network-extension`
- The mock evaluates `connect` events from eslogger against the same policy engine
- Decisions are logged but connections are NOT actually blocked
- Statistics are tracked and visible in the GUI dashboard

## Troubleshooting

### Extension not loading

1. Check that the extension is enabled in System Settings > Network Extensions.
2. Verify the extension is properly signed with Apple Developer entitlements.
3. Check Console.app for `ClawDefenderNetwork` log messages.
4. Restart the daemon: `clawdefender-daemon restart`.

### Connections not being filtered

1. Verify network filtering is enabled: `clawdefender network status`.
2. Check that the process is recognized as an agent (non-agent traffic is never filtered).
3. Review the network log for the connection decision.
4. Check if the destination matches an allowlist rule.

### Performance concerns

- The network extension uses a DNS cache (configurable TTL) to minimize lookup overhead.
- Policy decisions are cached per (host, port) pair.
- Rate limiting is per-PID and generates alerts only (does not block connections).
- If latency is observed, check the connection log for volume spikes.
