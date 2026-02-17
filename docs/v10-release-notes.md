# Phase 10 Release Notes — ClawDefender GUI Application

## Summary

Phase 10 delivers the **ClawDefender desktop GUI application**, a native Tauri v2 app built with React 19, TypeScript, and Tailwind CSS. The app provides a graphical interface for all ClawDefender functionality: real-time event monitoring, security policy management, prompt/alert handling, behavioral analysis, vulnerability scanning, and system health diagnostics.

## New features

### Tauri desktop application

- Native macOS application built with Tauri v2 for minimal resource usage
- Universal binary supporting both Apple Silicon and Intel Macs
- System tray integration with color-coded status icon (green/yellow/red)
- Auto-start at login via `tauri-plugin-autostart`
- Desktop notifications via `tauri-plugin-notification`
- Auto-update support via `tauri-plugin-updater`
- Minimize-to-tray behavior with background daemon monitoring

### Onboarding wizard

- Four-step first-run experience: Welcome, Detect & Protect, Security Level, Complete
- Automatic detection of MCP clients (Claude Desktop, VS Code, Cursor, Windsurf)
- One-click server wrapping with progress indicators
- Security level selection (Monitor Only, Balanced, Strict)
- Option to start at login and show in menu bar

### Dashboard

- Protection status hero banner with three states (Protected, Action Needed, Threat Detected)
- Quick stats: Events Today, Blocked, Pending Prompts, Active Guards
- Real-time activity feed showing the 10 most recent events
- Alerts panel for high-risk and critical events
- Server overview cards with status indicators

### Event timeline

- Virtualized scrolling for handling 10,000+ events without performance degradation
- Live streaming with auto-scroll and green "Live" indicator
- Full-text search across all event fields
- Filters: server dropdown, decision type pills (Allow/Deny/Prompt), blocks-only toggle
- Click-to-expand event detail panel with formatted JSON

### Policy editor

- Visual rule list with color-coded action icons (Block, Prompt, Allow, Audit)
- Rule editor modal for creating and editing rules
- Priority badges and hit counts for each rule
- Three-dot menu: duplicate, enable/disable, move up/down, delete
- Security level indicator with one-click level switching
- Template browser for applying pre-built policy templates

### Prompt and alert windows

- Prompt window with countdown timer bar, risk-level indicator, and action details
- Keyboard shortcuts: D (Deny), A (Allow Once), S (Session), P (Always)
- High-risk prompts show a warning banner and emphasize the Deny button
- Alert window with kill chain detection display and suspicious event list
- Queue indicator for multiple pending prompts

### Behavioral analysis

- Server behavioral profile cards with anomaly scores
- Status indicators: Learning, Normal, Anomalous
- Anomaly score visualization with color grading

### Scanner

- Vulnerability scan launcher with progress tracking
- Module-by-module progress with findings count

### Guards

- Agent self-protection guard status cards
- Trigger counts and last-triggered timestamps

### Audit log

- Historical event search and filtering
- Designed for investigation workflows

### System health

- Diagnostic checks with pass/warn/fail status
- Fix suggestions for failed checks
- System information display

### Settings

- Theme selection (Dark, Light, System)
- Notification toggle
- Auto-start daemon option
- Minimize to tray toggle
- Log level configuration
- Prompt timeout adjustment
- Event retention period

## Technical details

- **Framework**: Tauri v2 with Rust backend and web frontend
- **Frontend**: React 19 + TypeScript + Tailwind CSS v4
- **State management**: Zustand v5 with ring buffer event store (10,000 event cap)
- **Routing**: React Router v7 with sidebar navigation
- **IPC**: Tauri command system bridging React frontend to Rust daemon communication
- **Event streaming**: Tauri event system for real-time daemon-to-UI updates

## Distribution

- `.dmg` installer for macOS with universal binary
- Homebrew cask: `brew install --cask clawdefender`
- Auto-update via Tauri updater plugin
- Code signing and notarization for macOS Gatekeeper

## Keyboard shortcuts

| Shortcut | Context | Action |
|----------|---------|--------|
| D | Prompt window | Deny the request |
| A | Prompt window | Allow once |
| S | Prompt window | Allow for session |
| P | Prompt window | Allow permanently |

## Known limitations

- Linux and Windows builds are not yet available; macOS only for this release
- The GUI requires the ClawDefender daemon to be installed separately (bundled in the `.dmg`)
- Behavioral profile visualization is limited to summary cards; detailed charts are planned
- Audit log search does not yet support date range filtering in the UI (available via CLI)
- Custom themes beyond Dark/Light/System are not supported

## Breaking changes

None. Phase 10 is additive. All existing CLI, REST API, and SDK functionality continues to work unchanged.

## Migration from CLI/TUI

No migration is required. The GUI communicates with the same daemon and reads the same configuration files as the CLI. Users can switch freely between the GUI and CLI.

- Policies created via CLI are visible in the GUI Policy Editor
- Events from CLI-wrapped servers appear in the GUI Timeline
- Guards registered via the SDK appear in the GUI Guards page
- Settings changed in the GUI are written to the same `config.toml` used by the CLI
