# Rookbot System Requirements

## Operating System

- **macOS 13.0 (Ventura) or later** -- required for eslogger (Endpoint Security)
- Works on macOS 14 (Sonoma), 15 (Sequoia), and 26 (Tahoe)
- Older macOS versions will build but eslogger-based monitoring will not function

## Architecture

- **Apple Silicon (arm64)**: Fully supported, primary development target
- **Intel (x86_64)**: Supported; llama.cpp compiles with AVX/AVX2/FMA/F16C SIMD optimizations via the `native` feature

## Rust Toolchain

- **Rust stable channel** (tested with rustc 1.93.1)
- Components: `rustfmt`, `clippy` (specified in `rust-toolchain.toml`)
- Install via: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

## Build Dependencies

### Required

- **Xcode Command Line Tools**: Provides the C/C++ compiler (`cc`/`clang`) needed by `llama_cpp_sys`, `ring`, and `rusqlite` (bundled SQLite)
  ```
  xcode-select --install
  ```

- **C++ Standard Library**: Required by `llama_cpp_sys` (linked via `link-cplusplus`)

### NOT Required

- **CMake**: The `llama_cpp_sys` crate uses the `cc` crate for its build system, not CMake. No CMake installation is needed.
- **Homebrew packages**: No external library dependencies beyond what Xcode CLT provides

### Optional

- **just** (command runner): Used for build/install convenience targets in the `justfile`. Install via `cargo install just` or `brew install just`

## System Frameworks (Linked Automatically)

The following macOS frameworks are linked at runtime (provided by the OS, no user action needed):

- `CoreFoundation.framework` -- used by Rust runtime / networking
- `Security.framework` -- used by `rustls` / TLS stack
- `SystemConfiguration.framework` -- used by networking (DNS resolution)
- `IOKit.framework` -- used by system info queries (daemon only)
- `CoreServices.framework` -- used by filesystem watcher / FSEvents (daemon only)
- `libc++` -- C++ standard library, used by `llama_cpp_sys` (CLI)
- `libobjc` -- Objective-C runtime, used transitively (daemon)

## Feature-Specific Requirements

### SLM / AI Model Inference (`gguf` feature)

- The `llama_cpp` v0.3.2 crate compiles llama.cpp from source via the `cc` crate
- Default features enable CPU-only inference with native SIMD optimizations
- **Metal GPU acceleration** requires enabling the `metal` feature on `llama_cpp`:
  ```toml
  llama_cpp = { version = "0.3", features = ["metal"] }
  ```
  Note: This is NOT currently enabled in the workspace. The `n_gpu_layers` setting in `gguf_backend.rs` is a no-op without Metal support.

### Endpoint Security Monitoring (`eslogger`)

- Requires **macOS 13.0+** (Ventura)
- Requires **Full Disk Access (FDA)** for the daemon process
- Requires running with `sudo` privileges (eslogger uses Endpoint Security entitlements)
- The sensor crate handles missing eslogger gracefully: version check, binary existence check, and FDA detection are all performed before attempting to start
- On older macOS or non-macOS platforms, the eslogger manager returns an error; the rest of the system continues to function

### Tauri Desktop App

Additional requirements for building the GUI:

- **Node.js** (v18+) and npm/pnpm for the frontend
- **WebKit/WKWebView** (provided by macOS)
- Tauri 2.x plugins: shell, autostart, notification, updater, process

## Runtime Requirements

### Directory layout

| Path | Purpose |
|------|---------|
| `~/.config/rookbot/` | Config: `config.toml`, `policy.toml`, `sensor.toml`, `noise.toml` |
| `~/.local/share/rookbot/` | Data: `audit.jsonl`, `clawdefender.pid`, `clawdefender.sock`, `server-token`, databases |
| `~/.local/share/rookbot/models/` | GGUF model files for AI inference |
| `~/.local/share/rookbot/threat-intel/` | Threat intelligence feeds and blocklists |
| `~/.local/share/rookbot/crashes/` | Crash reports |
| `~/.local/share/rookbot/scans/` | Scan results |

### Notes

- The IPC socket is created at `~/.local/share/rookbot/clawdefender.sock`
- The `server-token` file (0600 permissions) is used for daemon authentication
- The project uses XDG-style paths (`~/.config/`, `~/.local/share/`) on all platforms, NOT macOS-native `~/Library/Application Support/`
- When `$HOME` is not set, fallback paths under `/tmp/clawdefender/` are used

## Release Build Profile

The workspace uses an aggressive release profile:

```toml
[profile.release]
lto = "fat"          # Full link-time optimization
codegen-units = 1    # Single codegen unit for maximum optimization
strip = true         # Strip debug symbols
opt-level = "z"      # Optimize for binary size
panic = "abort"      # Abort on panic (smaller binaries)
```

Release binary sizes (Apple Silicon):
- `clawdefender-daemon`: ~5.5 MB
- `clawdefender` (CLI): ~5.3 MB
