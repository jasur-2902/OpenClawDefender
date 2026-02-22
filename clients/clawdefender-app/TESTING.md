# ClawDefender Desktop App — Testing Guide

## Prerequisites
- macOS 13.0+ (Ventura or later)
- Rust toolchain (rustup)
- Node.js 18+
- Tauri CLI: `cargo install tauri-cli`

## Running Tests

### Unit Tests
```
cd clients/clawdefender-app/src-tauri && cargo test
```
Expected: 57+ tests pass

### TypeScript Check
```
cd clients/clawdefender-app && npx tsc --noEmit
```

### Clippy
```
cd clients/clawdefender-app/src-tauri && cargo clippy -- -D warnings
```

## Manual Testing Checklist

### Installation
- [ ] Open .dmg — verify professional layout (icon + Applications folder + background)
- [ ] Drag to Applications — verify copy succeeds
- [ ] Launch from Applications (first time: right-click → Open for unsigned)

### First Launch
- [ ] Onboarding wizard appears
- [ ] MCP client detection runs (or shows "no clients found")
- [ ] Security level selection works
- [ ] "Start at Login" checkbox works
- [ ] Clicking "Open Dashboard" transitions to main app

### Dashboard & Navigation
- [ ] Sidebar shows all navigation items
- [ ] Daemon status indicator (green dot = running)
- [ ] Each page loads without errors

### Tray Icon
- [ ] Shield icon appears in menu bar with correct status color
- [ ] Tooltip shows "ClawDefender — Protected (N servers)" or "Not Running"
- [ ] Tray menu shows: status, server count, prompts, blocks, navigation items, pause/resume, quit

### Window Management
- [ ] Close button (red X) hides to tray, doesn't quit
- [ ] Click tray icon restores window
- [ ] Cmd+Q quits the app (stops daemon if started by GUI)

### Theme
- [ ] Settings → Theme → Dark: all pages dark
- [ ] Settings → Theme → Light: all pages light, text readable, badges visible
- [ ] Settings → Theme → System: follows macOS appearance
- [ ] Theme change is instant (no reload needed)
- [ ] Quit and relaunch: theme is preserved, no flash

### Notifications
- [ ] With window minimized/unfocused: trigger a prompt event → macOS notification appears
- [ ] Click notification → window comes to focus
- [ ] With window focused: no macOS notification (in-app UI only)
- [ ] Settings → Notifications toggle off → no macOS notifications

### Settings
- [ ] Start at Login toggle → check ~/Library/LaunchAgents/ for plist
- [ ] Export Config → file created on Desktop
- [ ] Import Config → select exported file, settings restored
- [ ] Reset to Defaults → confirmation dialog, then settings reset

### Autostart
- [ ] Enable "Start at Login" → verify plist exists: `ls ~/Library/LaunchAgents/ | grep -i claw`
- [ ] Disable → verify plist removed
- [ ] Relaunch app → toggle reflects actual OS state

## Build Output
- `.app` bundle: `src-tauri/target/release/bundle/macos/ClawDefender.app`
- `.dmg` installer: `src-tauri/target/release/bundle/dmg/ClawDefender_*.dmg`
- Expected .dmg size: ~10MB

## Known Issues
1. Updater pubkey is empty — auto-update disabled
2. Network Extension shows "Not Available" (requires system extension signing)
3. Daemon version hardcoded to 0.10.0 in System Health
4. 4 dead-code warnings from unused helper functions in daemon.rs and windows.rs (suppressed with #[allow(dead_code)])
