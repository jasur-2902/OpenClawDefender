# ClawDefender v0.3.0-beta — Desktop App Release

## What's New

### Phase 5: Polish & Ship
- **Professional App Identity** — Custom shield icon in Dock, menu bar, and DMG installer
- **macOS Notifications** — Native desktop notifications for security prompts, alerts, and auto-blocks when the app window isn't focused
- **Light & Dark Themes** — Complete light mode support with system theme detection and instant switching
- **Start at Login** — LaunchAgent-based autostart with toggle in Settings and Onboarding
- **Rich Tray Menu** — Shows protection status, server count, pending prompts, blocked actions, pause/resume control
- **Settings Export/Import** — Back up and restore configuration across machines (secrets automatically stripped)
- **DMG Installer** — Drag-to-install .dmg with professional layout

### Previous Phases (included)
- **Phase 4: Real Data** — All pages show real data from daemon, SQLite, and disk files. Zero mock data.
- **Phase 3: Live Events** — Real-time event streaming, audit history, prompt flow with Allow/Deny, alerts with Kill Process
- **Phase 2: Core Features** — MCP detection, wrap/unwrap, policy CRUD, settings persistence, onboarding
- **Phase 1: Daemon IPC** — Background connection monitor, real start/stop/status, tray reflects real state

## System Requirements
- macOS 13.0 (Ventura) or later
- Apple Silicon or Intel Mac

## Installation
1. Open `ClawDefender_0.3.0_aarch64.dmg` (or x86_64 variant)
2. Drag ClawDefender to Applications
3. **First launch (unsigned build):** Right-click the app → Open → click "Open" in the dialog
4. Complete the onboarding wizard
5. The daemon starts automatically

## Known Limitations
- **Unsigned build** — macOS Gatekeeper will warn on first launch. Use right-click → Open to bypass.
- **Network Extension** — Not active (requires macOS system extension signing). Network filtering shows "Not Available".
- **Auto-update** — Updater is configured but disabled (no signing key set). Manual updates required.
- **Universal binary** — Current build is architecture-specific. Run the build on each target architecture.

## Build from Source
```
just build-dmg        # Build unsigned .dmg
just build-dmg-target aarch64-apple-darwin  # Build for specific arch
```
