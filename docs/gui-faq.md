# ClawDefender GUI — Frequently Asked Questions

## General

### How do I add a new MCP server?

There are two ways:

1. **During onboarding**: ClawDefender automatically detects MCP clients and their servers. Select which servers to protect and click "Protect These."
2. **After setup**: Use the CLI command `claw wrap <client> <server>` to wrap additional servers. The Dashboard will update automatically once the daemon picks up the new configuration.

### Can I use ClawDefender without the GUI?

Yes. ClawDefender's core is a daemon that runs in the background. You can manage it entirely through the CLI:

- `claw daemon start` / `claw daemon stop` to manage the daemon
- `claw status` to check protection status
- `claw policy` to manage security rules
- `claw audit` to query the event log
- `claw scan` to run vulnerability scans

The GUI is a convenience layer that communicates with the same daemon via IPC.

### What happens when I close the window vs quit the app?

- **Close window** (red X or Cmd+W): If "Minimize to tray" is enabled in Settings, ClawDefender continues running in the system tray. The daemon stays active.
- **Quit** (Cmd+Q or tray menu > Quit): The app exits completely. If the daemon was started by the app and auto-start is enabled, the daemon continues running independently.

### Why does ClawDefender need Full Disk Access?

ClawDefender reads MCP client configuration files to detect servers and modify them for wrapping. On macOS, these files may be in locations that require Full Disk Access (e.g., Claude Desktop's config in `~/Library/Application Support/`). Without this permission, server detection may fail.

### How do I update ClawDefender?

ClawDefender supports auto-update. When an update is available:

1. A notification appears in the app
2. The update downloads in the background
3. Restart ClawDefender to apply the update

You can also update via Homebrew: `brew upgrade --cask clawdefender`

### How do I uninstall ClawDefender?

1. Quit ClawDefender from the system tray
2. Run `claw unwrap --all` to restore original MCP server configurations
3. Run `claw daemon stop` to stop the daemon
4. Delete `/Applications/ClawDefender.app`
5. Remove `~/.config/clawdefender/` (configuration) and `~/Library/Logs/clawdefender/` (logs)

If installed via Homebrew: `brew uninstall --cask clawdefender`

## Security and Policy

### What's the difference between Monitor Only, Balanced, and Strict?

| Level | Behavior |
|-------|----------|
| **Monitor Only** | All actions are allowed and logged. No blocking or prompting. Useful for observing agent behavior before enforcing rules. |
| **Balanced** | High-risk actions are blocked automatically. Sensitive operations trigger a prompt for your approval. Low-risk operations are allowed. This is the recommended setting. |
| **Strict** | All actions require explicit approval. Anything not matching an allow rule is denied. Best for high-security environments. |

### How do I create a custom security rule?

1. Navigate to the **Policy** page
2. Click **+ New Rule**
3. Fill in the fields:
   - **Name**: A descriptive name (e.g., "Block file deletion")
   - **Action**: Choose Deny, Prompt, Allow, or Audit
   - **Pattern**: A glob pattern matching the resources to target (e.g., `**/secrets/**`)
   - **Priority**: Higher numbers are evaluated first (0-100)
4. Click **Save**

Rules are evaluated in priority order. The first matching rule determines the action.

### How do I approve or deny a prompt?

When a prompt appears:

- Click one of the action buttons, or use keyboard shortcuts:
  - **D** = Deny
  - **A** = Allow Once
  - **S** = Allow for Session
  - **P** = Allow Permanently
- If you do nothing, the prompt auto-denies when the timer expires (default: 30 seconds)

For high-risk prompts, ClawDefender recommends denying and displays the Deny button prominently.

### What does the anomaly score mean?

The anomaly score (0.0 to 1.0) measures how much an MCP server's current behavior deviates from its learned baseline:

- **0.0 - 0.3**: Normal, consistent with past behavior
- **0.3 - 0.6**: Mild deviation, may warrant investigation
- **0.6 - 0.8**: Significant anomaly, review recommended
- **0.8 - 1.0**: Critical anomaly, possible compromise or misuse

ClawDefender builds behavioral profiles by observing server activity over time. New servers start in "learning" mode until enough data is collected.

## Dashboard and Events

### What do the tray icon colors mean?

| Color | Meaning |
|-------|---------|
| **Green** | Daemon running, no active threats or pending prompts |
| **Yellow** | Action needed: pending prompts or recent warnings |
| **Red** | Daemon stopped or critical threat detected |

### Why are events not appearing in the Timeline?

Check the following:

1. **Daemon status**: The sidebar should show "Daemon Running" with a green dot
2. **Server wrapping**: Ensure servers are wrapped (check Dashboard > Server Overview)
3. **Client restart**: After wrapping servers, restart your AI application (Claude Desktop, Cursor, etc.)
4. **Filters**: Clear any active filters in the Timeline filter bar

### How do I export event data?

Use the CLI to export events: `claw audit export --format json --output events.json`

You can filter by date range, server, and event type when exporting.

## Technical

### What ports does ClawDefender use?

ClawDefender communicates via Unix domain sockets (IPC), not TCP ports. The socket is located at the path shown in the daemon status (typically `~/.config/clawdefender/daemon.sock`).

### Does ClawDefender slow down my AI tools?

ClawDefender is designed for minimal latency. The proxy adds sub-millisecond overhead to MCP calls. The behavioral analysis engine runs asynchronously and does not block tool calls.

### Can I run multiple instances of ClawDefender?

No. Only one instance of the ClawDefender app can run at a time. The daemon is also a singleton — attempting to start a second daemon will fail gracefully.

### Where are logs stored?

- **macOS**: `~/Library/Logs/clawdefender/`
- **Linux**: `~/.local/share/clawdefender/logs/`

Set the log level in Settings (Trace, Debug, Info, Warn, Error).

### Where is the configuration stored?

Configuration files are in `~/.config/clawdefender/`:

- `config.toml` — App and daemon settings
- `policy.toml` — Security policy rules
- `profiles/` — Behavioral profiles
- `daemon.sock` — IPC socket
