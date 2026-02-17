# Menu Bar App Guide

ClawDefender includes a native macOS menu bar application built with SwiftUI for real-time monitoring and prompt handling.

## Installation

### Build from source

```bash
just build-menubar
```

Or manually:

```bash
cd clients/clawdefender-menubar
swift build -c release
```

The built binary is at `.build/release/ClawDefenderMenuBar`.

### Launch

Double-click the built app or run from the terminal:

```bash
./ClawDefenderMenuBar
```

The menu bar icon appears in the macOS menu bar. The app connects to the ClawDefender daemon automatically via the Unix domain socket at `~/.local/share/clawdefender/clawdefender.sock`.

## Usage

### Menu bar icon colors

| Color | Meaning |
|-------|---------|
| Green | All subsystems healthy, no pending alerts |
| Yellow | Warning: a subsystem is degraded (e.g., eslogger unavailable) |
| Red | Alert: uncorrelated activity detected or prompt pending |

### Dropdown menu

Click the menu bar icon to open the dropdown:

- **Status** -- Shows daemon connection state and subsystem health
- **Recent Alerts** -- Lists recent blocked events and uncorrelated activity
- **Pending Prompts** -- Shows tool calls awaiting user decision
- **Open Dashboard** -- Opens the full audit dashboard (if available)

### Prompt approvals

When a tool call matches a `prompt` policy rule, a prompt window appears:

1. The window shows the tool name, arguments, and risk assessment (if SLM is enabled)
2. Choose an action:
   - **Allow Once** -- permit this specific tool call
   - **Deny** -- block this tool call
3. The decision is sent to the daemon and the tool call proceeds or is blocked

### Alert handling

When uncorrelated activity is detected or an event is blocked:

1. A notification appears (if notifications are enabled in config)
2. The alert is listed in the Recent Alerts section
3. Click an alert to view details

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| D | Deny the current prompt |
| A | Allow Once for the current prompt |

## Connecting to the Daemon

The menu bar app connects to the daemon via IPC. The connection is established automatically on launch. If the daemon is not running:

1. The status shows "Disconnected"
2. The app retries the connection periodically
3. Start the daemon with `clawdefender daemon start` to restore the connection

### Connection configuration

The socket path defaults to `~/.local/share/clawdefender/clawdefender.sock`. This matches the daemon's default socket path configured in `~/.config/clawdefender/clawdefender.toml`.
