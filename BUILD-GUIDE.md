# Rookbot Build Guide

## Prerequisites

- **macOS 13.0+** (Ventura or later) -- required for full functionality (eslogger)
- **Xcode Command Line Tools** -- provides C/C++ compiler for native dependencies
  ```
  xcode-select --install
  ```
- **Rust stable toolchain** (1.93.1 or later)
  ```
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **CMake is NOT required** -- llama.cpp builds via the `cc` crate

For Tauri desktop app builds, also install:
- **Node.js v18+** and npm/pnpm

See `SYSTEM-REQUIREMENTS.md` for full details including macOS framework dependencies and architecture notes.

## Clone

```bash
git clone <repo-url> clawai
cd clawai
```

## Build (Debug)

Build the entire workspace:

```bash
cargo build --workspace
```

Build individual binaries:

```bash
cargo build -p clawdefender-daemon    # Daemon
cargo build -p clawdefender-cli       # CLI (binary name: clawdefender)
```

Build the SLM crate with all features:

```bash
cargo build -p clawdefender-slm --features "gguf,cloud,download"
```

Build without GGUF (uses mock SLM backend):

```bash
cargo build -p clawdefender-daemon --no-default-features
```

## Build (Release)

```bash
cargo build --release -p clawdefender-daemon
cargo build --release -p clawdefender-cli
```

Release binaries are written to `target/release/`. The release profile uses fat LTO, single codegen unit, symbol stripping, and size optimization. Expect ~60-70s build time per binary.

## Run Tests

```bash
cargo test --workspace
```

15 tests are `#[ignore]`-annotated because they require runtime dependencies (running daemon, eslogger privileges, or network access).

## Install

The recommended install method uses the install script, which builds from source, creates directories, writes default configs, and sets up the macOS LaunchAgent:

```bash
bash scripts/install.sh
```

This script:
1. Builds release binaries for `clawdefender` (CLI) and `clawdefender-daemon`
2. Copies binaries to `/usr/local/bin/` (override with `CLAWDEFENDER_INSTALL_DIR`)
3. Creates `~/.config/rookbot/` with default `config.toml` and `policy.toml`
4. Creates `~/.local/share/rookbot/` with subdirectories: `models/`, `threat-intel/`, `crashes/`, `scans/`
5. Generates a `server-token` (0600 permissions) for daemon authentication
6. Installs and loads a LaunchAgent plist (`com.clawdefender.daemon`)
7. Runs `clawdefender init` for honeypot setup and client detection

Alternatively, using `just`:

```bash
just install           # Full install (same as scripts/install.sh)
just install-quick     # Quick: copy binaries only, no dirs/plist
just install-local     # Quick install + clawdefender init
```

## Verify Installation

Check that binaries are on PATH:

```bash
which clawdefender
which clawdefender-daemon
```

Check versions:

```bash
clawdefender --version
clawdefender-daemon --version
```

Verify config and data directories exist:

```bash
ls ~/.config/rookbot/
ls ~/.local/share/rookbot/
```

## Run the Daemon

If installed via `scripts/install.sh`, the daemon is already running as a LaunchAgent. Check its status:

```bash
launchctl list | grep clawdefender
```

To start/stop manually:

```bash
launchctl load ~/Library/LaunchAgents/com.clawdefender.daemon.plist
launchctl unload ~/Library/LaunchAgents/com.clawdefender.daemon.plist
```

To run the daemon directly (foreground, for development):

```bash
clawdefender-daemon
```

Or from the build directory:

```bash
./target/release/clawdefender-daemon
```

The daemon creates an IPC socket at `~/.local/share/rookbot/clawdefender.sock` and writes its PID to `~/.local/share/rookbot/clawdefender.pid`.

## Uninstall

```bash
bash scripts/uninstall.sh
```

Or:

```bash
just uninstall
```

## Directory Layout

| Directory | Purpose |
|-----------|---------|
| `~/.config/rookbot/` | Configuration: `config.toml`, `policy.toml`, `sensor.toml` |
| `~/.local/share/rookbot/` | Runtime data: audit logs, databases, PID file, socket, server-token |
| `~/.local/share/rookbot/models/` | GGUF model files for AI inference |
| `~/.local/share/rookbot/threat-intel/` | Threat intelligence feeds and blocklists |
| `/usr/local/bin/` | Installed binaries |

## Troubleshooting

### `xcode-select: error: command line tools are not installed`

Run `xcode-select --install` and accept the license. Wait for the download to complete before retrying the build.

### Linker errors mentioning `llama_cpp_sys` or C++ symbols

Ensure Xcode Command Line Tools are installed and up to date. On Apple Silicon, verify you are not running under Rosetta: `uname -m` should print `arm64`.

### `cargo build -p clawdefender-daemon --features gguf` fails

This is expected if you also pass `--no-default-features`. The `gguf` feature is included in the default features. Use either `cargo build -p clawdefender-daemon` (default includes gguf) or `cargo build -p clawdefender-daemon --features gguf`.

### Daemon fails to start: "Address already in use"

Another daemon instance is running. Check with `launchctl list | grep clawdefender` or look for the PID file at `~/.local/share/rookbot/clawdefender.pid`.

### eslogger errors: "macOS X.Y is not supported"

eslogger requires macOS 13.0 (Ventura) or later. On older macOS, the daemon still runs but without Endpoint Security monitoring.

### eslogger errors: "Full Disk Access required"

The daemon (or terminal running it) needs Full Disk Access. Grant it in System Settings > Privacy & Security > Full Disk Access.

### Server-token authentication failures

Ensure both the daemon and CLI/app read the same token file at `~/.local/share/rookbot/server-token`. If the file is missing, run `scripts/install.sh` or manually generate one:

```bash
head -c 32 /dev/urandom | base64 > ~/.local/share/rookbot/server-token
chmod 0600 ~/.local/share/rookbot/server-token
```

### GPU inference not working (CPU-only)

Metal GPU acceleration is not compiled in by default. The `n_gpu_layers` config setting is a no-op without the `metal` feature. To enable Metal, edit `crates/clawdefender-slm/Cargo.toml`:

```toml
llama_cpp = { version = "0.3", optional = true, features = ["metal"] }
```

Then rebuild. This is a known limitation documented in `SYSTEM-REQUIREMENTS.md`.

### LaunchAgent plist: paths contain `~` or `$HOME`

macOS plists do not expand `~` or `$HOME`. Use `scripts/install.sh` which generates the plist with correct absolute paths. If you installed manually, edit the plist at `~/Library/LaunchAgents/com.clawdefender.daemon.plist` and replace any `~` with your full home directory path.
