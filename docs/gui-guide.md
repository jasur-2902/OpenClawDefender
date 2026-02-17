# ClawDefender GUI User Guide

## Installation

### macOS (.dmg)

1. Download the latest `ClawDefender_x.x.x_universal.dmg` from the releases page
2. Open the `.dmg` file and drag **ClawDefender** into your Applications folder
3. Launch ClawDefender from Applications or Spotlight

On first launch, macOS may ask you to confirm opening an app from an identified developer. Click **Open** to proceed.

### Homebrew

```bash
brew install --cask clawdefender
```

### Auto-update

ClawDefender checks for updates automatically. When an update is available, you will see a notification in the app. Updates are downloaded and applied in the background; a restart is required to complete the update.

## First Launch and Onboarding

When you open ClawDefender for the first time, an onboarding wizard guides you through initial setup in four steps:

### Step 1: Welcome

A brief introduction to what ClawDefender does. Click **Get Started** to continue.

### Step 2: Detect and Protect

ClawDefender scans your system for MCP clients (Claude Desktop, VS Code with Copilot, Cursor, etc.) and lists the MCP servers each client has configured. Select which servers to protect and click **Protect These**. ClawDefender wraps each selected server so that all traffic is routed through the security proxy.

If no clients are detected, you can skip this step and add servers manually later.

### Step 3: Choose Security Level

Pick a security posture:

| Level | Behavior |
|-------|----------|
| **Monitor Only** | Logs all activity without blocking. Good for observation before enforcing rules. |
| **Balanced** (recommended) | Blocks high-risk actions and prompts for sensitive operations. |
| **Strict** | Prompts for all actions and denies anything not explicitly allowed. |

You can change the security level at any time from the Policy page or Settings.

### Step 4: Complete

Review the list of protected servers, choose whether to start ClawDefender at login and show the menu bar icon, then click **Open Dashboard**.

> After completing onboarding, restart any running AI applications so they use the protected server configurations.

## Dashboard

The Dashboard is the home screen of ClawDefender. It provides an at-a-glance view of your security posture.

### Protection Status

The large banner at the top shows one of three states:

- **You're Protected** (green): Daemon is running, no unresolved threats
- **Action Needed** (yellow): There are pending prompts or recently blocked actions
- **Threat Detected** (red): The daemon is not running or a critical event occurred

### Quick Stats

Four cards summarize key metrics:

- **Events Today**: Total number of MCP events recorded
- **Blocked**: Number of actions that were denied
- **Pending Prompts**: Actions waiting for your decision
- **Active Guards**: Number of agent self-protection guards currently active

### Recent Activity

A live feed of the most recent 10 events, showing the time, server name, tool or event type, and the decision (Allowed, Blocked, or Prompted).

### Alerts

High-risk and critical events are surfaced in the alerts panel on the right side. Each alert shows the risk level, a description, the server name, and the time.

### Server Overview

Cards for each monitored MCP server showing the server name, status (running, stopped, error), event count, and whether it is wrapped by ClawDefender.

## Event Timeline

The Timeline provides a detailed, chronological view of all MCP events.

### Filtering

Use the filter bar at the top to narrow down events:

- **Search**: Type keywords to search across server names, tool names, event types, actions, and details
- **Server**: Select a specific MCP server from the dropdown
- **Status pills**: Click Allow, Deny, or Prompt to filter by decision type
- **Only blocks**: Check this to show only blocked/denied events

### Investigating Events

Click on any event row to open the detail panel. The panel shows:

- Event ID, timestamp, server, event type
- Tool name and action
- Decision and risk level
- Resource path
- Full details (formatted JSON when available)

Click **Close** to dismiss the detail panel.

### Live Mode

The timeline streams events in real time. A green "Live" indicator appears in the header. Scroll down to pause auto-scroll; click **Scroll to latest** to resume.

### Virtualized Scrolling

The timeline uses virtualized scrolling for performance, rendering only the visible rows even when thousands of events are recorded.

## Policy Editor

The Policy Editor lets you create and manage security rules that control how ClawDefender handles MCP traffic.

### Rules List

Each rule displays:

- **Action icon**: Color-coded indicator (red = Block, yellow = Prompt, green = Allow, blue = Audit)
- **Name and pattern**: Human-readable name and the glob pattern it matches
- **Priority**: Higher priority rules are evaluated first
- **Hit count**: How many times the rule has been triggered
- **Enabled/Disabled**: Dimmed rules are disabled

### Creating a Rule

1. Click **+ New Rule** in the top right
2. Fill in the rule editor modal:
   - **Name**: Descriptive name for the rule
   - **Description**: What the rule does
   - **Action**: Allow, Deny, Prompt, or Audit
   - **Resource**: The resource scope (use `*` for all)
   - **Pattern**: Glob pattern to match (e.g., `/etc/**`, `tool://write_file`)
   - **Priority**: 0-100, higher means evaluated first
   - **Enabled**: Toggle on or off
3. Click **Save**

### Rule Actions

Right-click or use the three-dot menu on any rule to:

- **Edit**: Open the rule in the editor
- **Duplicate**: Create a copy of the rule
- **Enable/Disable**: Toggle the rule
- **Move Up/Down**: Change evaluation order
- **Delete**: Remove the rule

### Security Level

The current security level is shown at the top of the Policy page. Click **Change Level** to switch between Monitor Only, Balanced, and Strict.

### Templates

Click **Change Template** to browse pre-built policy templates for common use cases. Click **Reset** to reload the policy from disk.

## Behavioral Analysis

The Behavioral page shows AI agent behavioral profiles and anomaly detection.

### Server Profiles

Each monitored server has a behavioral profile card showing:

- **Server name** and status (normal, learning, anomalous)
- **Anomaly score**: 0.0 (normal) to 1.0 (highly anomalous)
- **Total calls** and **tools count**
- **Last activity** timestamp

### Understanding Anomaly Scores

- **0.0 - 0.3**: Normal behavior, consistent with learned patterns
- **0.3 - 0.6**: Mild deviation, may warrant investigation
- **0.6 - 0.8**: Significant anomaly, review recommended
- **0.8 - 1.0**: Critical anomaly, possible compromise or misuse

### Status Meanings

- **Learning**: ClawDefender is building a baseline profile for this server
- **Normal**: Server behavior matches the learned baseline
- **Anomalous**: Server behavior deviates significantly from baseline

## Scanner

The Scanner page lets you run vulnerability scans against your MCP server configurations.

### Running a Scan

1. Click **Start Scan** to begin
2. The progress bar shows completion percentage and the current module being scanned
3. When complete, findings are listed with severity levels

### Scan Modules

The scanner checks for common misconfigurations, exposed credentials, overly permissive permissions, and known vulnerabilities in MCP server setups.

## Guards

The Guards page displays the status of agent self-protection guards.

Each guard card shows:

- **Guard name** and type
- **Enabled/Disabled** status
- **Trigger count**: How many times the guard has been triggered
- **Last triggered**: When the guard last activated
- **Description**: What the guard protects against

## Audit Log

The Audit Log provides a searchable, historical view of all events. Unlike the Timeline which focuses on the live stream, the Audit Log is optimized for historical investigation.

### Searching

Use the search bar to find events by keyword. Results include timestamps, server names, actions, decisions, and details.

### Filtering

Filter by date range, server, event type, decision, and risk level to narrow down results.

## System Health

The System Health page runs diagnostic checks on your ClawDefender installation.

### Diagnostics

Each check shows:

- **Status**: Pass (green), Warning (yellow), or Fail (red)
- **Check name**: What was tested
- **Message**: Result description
- **Fix suggestion**: When a check fails, a suggested remediation is shown

### System Information

The page also displays system details:

- OS and version
- Architecture
- Daemon version
- App version
- Configuration directory
- Log directory

## Settings

The Settings page lets you configure ClawDefender's behavior.

| Setting | Description |
|---------|-------------|
| **Theme** | Dark, Light, or System (follows OS preference) |
| **Notifications** | Enable or disable desktop notifications |
| **Auto-start daemon** | Automatically start the daemon when the app launches |
| **Minimize to tray** | When closing the window, keep running in the system tray |
| **Log level** | Trace, Debug, Info, Warn, or Error |
| **Prompt timeout** | Seconds to wait before auto-denying a prompt (default: 30) |
| **Event retention** | Number of days to keep event history |

## Prompt Window

When an MCP action triggers a "prompt" decision, a prompt window appears requiring your approval.

### Layout

- **Timer bar**: Countdown until auto-deny (color changes from blue to yellow to red)
- **Risk indicator**: Color-coded dot and label showing the risk level
- **Details**: Server name, tool name, action, resource, and additional context
- **High-risk banner**: For high/critical risk events, a red banner recommends denying

### Making a Decision

| Button | Shortcut | Meaning |
|--------|----------|---------|
| Deny | D | Block this action |
| Allow Once | A | Allow this specific invocation only |
| Session | S | Allow for the current session |
| Always | P | Permanently allow this action pattern |

For high-risk prompts, the Deny button is prominently displayed and the other options are smaller.

### Queue

If multiple prompts arrive, a queue indicator at the bottom shows how many are pending.

## System Tray

ClawDefender runs in the system tray (menu bar on macOS) when minimized.

### Tray Icon Colors

| Color | Meaning |
|-------|---------|
| Green | Everything is healthy, daemon running, no threats |
| Yellow | Action needed: pending prompts or warnings |
| Red | Threat detected or daemon is not running |

### Tray Menu

Right-click (or click on macOS) the tray icon to:

- Open the main window
- View quick status
- Quit ClawDefender

## Keyboard Shortcuts

| Shortcut | Context | Action |
|----------|---------|--------|
| D | Prompt window | Deny the request |
| A | Prompt window | Allow once |
| S | Prompt window | Allow for session |
| P | Prompt window | Allow permanently |

## Troubleshooting

### ClawDefender says "Daemon Stopped"

1. Open System Health and run diagnostics
2. Check that the daemon binary is installed (`claw doctor`)
3. If auto-start is enabled, the daemon should restart automatically
4. Manually start with `claw daemon start` from a terminal

### Prompts are auto-denying too quickly

Increase the prompt timeout in Settings. The default is 30 seconds.

### No MCP servers detected during onboarding

- Ensure your MCP client (Claude Desktop, Cursor, etc.) is installed and has been launched at least once
- Check that the client's MCP configuration file exists
- You can add servers manually from the Dashboard or via the CLI

### Events are not appearing in the Timeline

- Verify the daemon is running (check the sidebar status indicator)
- Make sure the MCP servers are wrapped (check Server Overview on the Dashboard)
- Restart your AI application after wrapping servers

### ClawDefender is using too much memory

The event ring buffer is capped at 10,000 events in memory. If you see high memory usage, reduce the event retention period in Settings.

### macOS asks for Full Disk Access

ClawDefender needs to read MCP client configuration files (e.g., Claude Desktop's `claude_desktop_config.json`) to detect and wrap servers. Grant Full Disk Access in System Settings > Privacy & Security > Full Disk Access.

### How to completely uninstall

1. Quit ClawDefender from the tray menu
2. Run `claw daemon stop` to stop the daemon
3. Delete `/Applications/ClawDefender.app`
4. Remove `~/.config/clawdefender/` for configuration
5. Remove `~/Library/Logs/clawdefender/` for logs
6. Optionally run `claw unwrap --all` before uninstalling to restore original MCP configurations
