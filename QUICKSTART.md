# ClawDefender Quick Start Guide

Get ClawDefender running and protecting your AI agents in under 10 minutes.

## Prerequisites

- **macOS 13 (Ventura)** or later
- **Xcode Command Line Tools** -- `xcode-select --install`
- **Rust toolchain** -- `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js 18+** -- required only for the GUI app (`brew install node`)
- **Homebrew** (optional) -- for installing dependencies

Verify your setup:

```bash
sw_vers -productVersion   # Should be 13.0 or later
rustc --version           # Should be 1.70+
cargo --version
```

## Step 1: Build from Source

```bash
git clone https://github.com/clawdefender/clawdefender.git
cd clawdefender
cargo build --workspace --release
```

Expected output (final lines):

```
   Compiling clawdefender-daemon v0.5.0-beta
   Compiling clawdefender v0.5.0-beta
    Finished `release` profile [optimized] target(s) in 68s
```

## Step 2: Install Binaries

```bash
# Install CLI and daemon to /usr/local/bin
sudo cp target/release/clawdefender /usr/local/bin/
sudo cp target/release/clawdefender-daemon /usr/local/bin/
```

Or use the justfile:

```bash
just install
```

## Step 3: Initialize Configuration

```bash
clawdefender init
```

Expected output:

```
Created config directory: ~/.config/clawdefender/
Created data directory: ~/.local/share/clawdefender/
Written default config: ~/.config/clawdefender/config.toml
Written default policy: ~/.config/clawdefender/policy.toml
ClawDefender initialized.
```

This creates:
- `~/.config/clawdefender/config.toml` -- main configuration
- `~/.config/clawdefender/policy.toml` -- security rules
- `~/.local/share/clawdefender/` -- audit logs, models, scan results

## Step 4: Start the Daemon

```bash
clawdefender daemon start
```

Expected output:

```
Starting ClawDefender daemon...
Daemon started (PID 12345).
```

Verify it is running:

```bash
clawdefender daemon status
```

Expected output:

```
ClawDefender Daemon
  Status: running
  PID: 12345
  Version: 0.5.0-beta
  Uptime: 5s
  Subsystems:
    Policy Engine: active (12 rules loaded)
    Audit Logger: active
    Behavioral Engine: learning
    SLM: disabled (no model)
```

## Step 5: Download and Activate an AI Model

Download a small language model for on-device risk analysis:

```bash
# Download the recommended model (~1 GB)
clawdefender model download qwen3-1.7b
```

Expected output:

```
Downloading qwen3-1.7b (1.1 GB)...
[========================================] 100% (1.1 GB)
Verifying SHA-256 checksum... OK
Model saved to ~/.local/share/clawdefender/models/qwen3-1.7b-q4_k_m.gguf
```

Activate the model:

```bash
clawdefender model set qwen3-1.7b
clawdefender model on
```

Verify with:

```bash
clawdefender model list
```

Expected output:

```
Available models:
  * qwen3-1.7b          [installed] [active]  Q4_K_M, 1.1 GB, Chat template: Qwen
    tinyllama-1.1b       [not installed]       Q4_K_M, 637 MB
    phi-4-mini           [not installed]       Q4_K_M, 2.2 GB
    gemma-3-1b           [not installed]       Q4_K_M, 815 MB
    smollm2-360m         [not installed]       Q4_K_M, 229 MB
```

Smaller models (smollm2-360m, tinyllama-1.1b) use less RAM and run faster, but are less accurate. The qwen3-1.7b model is recommended for Apple Silicon Macs.

## Step 6: Protect an MCP Server

Wrap a server so ClawDefender intercepts all tool calls:

```bash
# Wrap a specific server from your Claude Desktop config
clawdefender wrap filesystem-server

# Or wrap all configured servers at once
clawdefender wrap --all
```

Expected output:

```
Wrapped server "filesystem-server" for Claude Desktop.
Original config backed up to ~/.config/clawdefender/backups/
Restart Claude Desktop to activate protection.
```

Restart your MCP client (Claude Desktop, Cursor) for the changes to take effect.

## Step 7: Run a Security Scan

Scan an MCP server for vulnerabilities:

```bash
clawdefender scan -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

The scanner runs 5 modules:
1. **Config Audit** -- checks MCP client configuration for insecure settings
2. **Policy Strength** -- evaluates your policy rules for gaps
3. **System Posture** -- checks macOS security settings (SIP, Gatekeeper, FileVault)
4. **Behavioral Anomaly** -- tests for runtime behavioral deviations
5. **Fuzzing** -- sends malformed inputs to test server robustness

## Step 8: Check the Audit Log

View recent security events:

```bash
# Show the last 20 events
clawdefender log -n 20

# Show only blocked events
clawdefender log --blocked

# Show aggregate statistics
clawdefender log --stats
```

## Step 9: Set Up Threat Intelligence (Optional)

Update the threat feed and check server reputation:

```bash
clawdefender feed update
clawdefender reputation filesystem-server
```

Add custom indicators of compromise:

```bash
clawdefender ioc add domain evil-mcp-server.com
clawdefender ioc test evil-mcp-server.com
```

## Step 10: Cloud Escalation (Optional)

For deeper analysis of ambiguous events, configure a cloud API key:

```bash
clawdefender config set-api-key --provider anthropic
# Paste your API key when prompted
```

Edit `~/.config/clawdefender/config.toml` to enable escalation:

```toml
[swarm]
enabled = true
escalation_threshold = "MEDIUM"
daily_budget_usd = 1.00
monthly_budget_usd = 20.00
```

Monitor usage:

```bash
clawdefender usage
```

---

## Troubleshooting

### Daemon won't start

```bash
# Check if already running
clawdefender daemon status

# Check for stale PID file
ls -la ~/.local/share/clawdefender/clawdefender.pid

# Force stop and restart
clawdefender daemon stop
clawdefender daemon start

# Check daemon logs
cat ~/.local/share/clawdefender/daemon.log | tail -50
```

### Full Disk Access not granted

The OS sensor (eslogger) requires Full Disk Access. Without it, the daemon still works but OS-level monitoring is disabled.

To grant FDA:
1. Open **System Settings > Privacy & Security > Full Disk Access**
2. Click the **+** button
3. Add `/usr/local/bin/clawdefender-daemon`
4. Restart the daemon: `clawdefender daemon restart`

### Model download fails

```bash
# Check network connectivity
curl -I https://huggingface.co

# Try a smaller model first
clawdefender model download smollm2-360m

# Check available disk space (models are 200 MB to 2.2 GB)
df -h ~/.local/share/clawdefender/models/
```

### MCP server not intercepted after wrapping

1. Verify the wrap was applied: `clawdefender status`
2. Restart your MCP client (Claude Desktop, Cursor)
3. Check that the client config was modified: look for `clawdefender proxy --` in your MCP client config file

### Compile errors building from source

```bash
# Ensure Rust toolchain is up to date
rustup update

# Clean and rebuild
cargo clean
cargo build --workspace --release
```

---

## GUI App (Optional)

Build and run the Tauri desktop application:

```bash
# Install frontend dependencies
cd clients/clawdefender-app
npm install

# Run in development mode (from repo root)
just dev-app

# Or build a release .dmg
just build-dmg
```

The GUI provides a visual dashboard for alerts, events, prompts, settings, and AI analysis.

---

## Useful Commands Reference

| Command | Description |
|---------|-------------|
| `clawdefender daemon start/stop/restart/status` | Manage the background daemon |
| `clawdefender wrap <server>/--all` | Protect MCP servers |
| `clawdefender unwrap <server>` | Remove protection from a server |
| `clawdefender model list/download/set/on/off` | Manage AI models |
| `clawdefender scan -- <server-cmd>` | Run security scan |
| `clawdefender log [-n 50] [--blocked] [--stats]` | View audit log |
| `clawdefender policy list/reload/test` | Manage security policies |
| `clawdefender feed update/status/verify` | Manage threat intelligence |
| `clawdefender ioc status/add/test` | Manage indicators of compromise |
| `clawdefender reputation <server>` | Check server reputation |
| `clawdefender doctor` | Run diagnostic checks |
| `clawdefender config set-api-key` | Configure cloud API keys |
| `clawdefender usage` | View cloud API usage and costs |

## Configuration Files

| File | Purpose |
|------|---------|
| `~/.config/clawdefender/config.toml` | Main configuration |
| `~/.config/clawdefender/policy.toml` | Security policy rules |
| `~/.local/share/clawdefender/audit.jsonl` | Audit log (JSONL) |
| `~/.local/share/clawdefender/daemon.log` | Daemon log (rotated) |
| `~/.local/share/clawdefender/models/` | Downloaded AI models |
| `~/.local/share/clawdefender/threat-intel/` | Threat feed data |
| `~/.local/share/clawdefender/scans/` | Scan results |
