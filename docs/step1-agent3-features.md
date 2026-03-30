# Agent 3: Feature Flag Propagation Fixes

## Problem

The `clawdefender-daemon`, `clawdefender-cli`, and `clawdefender-app` (Tauri) crates
hardcoded SLM feature flags in their `[dependencies]` sections:

```toml
# Daemon & CLI had:
clawdefender-slm = { path = "...", features = ["gguf"] }

# Tauri app had:
clawdefender-slm = { path = "...", features = ["cloud", "download", "gguf"] }
```

This meant `cargo build -p clawdefender-daemon --features gguf` would fail because
the daemon did not define `gguf` as its own feature. Features could not be
selectively enabled/disabled at the consumer level.

## Changes

### 1. `crates/clawdefender-daemon/Cargo.toml`

- Removed hardcoded `features = ["gguf"]` from the `clawdefender-slm` dependency.
- Added `[features]` section:
  ```toml
  [features]
  default = ["gguf"]
  gguf = ["clawdefender-slm/gguf"]
  cloud = ["clawdefender-slm/cloud"]
  download = ["clawdefender-slm/download"]
  ```

### 2. `clients/clawdefender-cli/Cargo.toml`

- Removed hardcoded `features = ["gguf"]` from the `clawdefender-slm` dependency.
- Added `[features]` section:
  ```toml
  [features]
  default = ["gguf"]
  gguf = ["clawdefender-slm/gguf"]
  cloud = ["clawdefender-slm/cloud"]
  download = ["clawdefender-slm/download"]
  ```

### 3. `clients/clawdefender-app/src-tauri/Cargo.toml`

- Removed hardcoded `features = ["cloud", "download", "gguf"]` from the `clawdefender-slm` dependency.
- Added `[features]` section:
  ```toml
  [features]
  default = ["gguf", "cloud", "download"]
  gguf = ["clawdefender-slm/gguf"]
  cloud = ["clawdefender-slm/cloud"]
  download = ["clawdefender-slm/download"]
  ```

### 4. `crates/clawdefender-mcp-proxy/Cargo.toml`

No changes needed. The mcp-proxy only uses non-feature-gated SLM modules
(`analyzer`, `context`, `noise_filter`, `SlmService`) and already depends on
`clawdefender-slm` with no features.

## SLM cfg gate verification

All `#[cfg(feature = "...")]` gates in `crates/clawdefender-slm/src/` are correct:

| Feature    | Module           | Fallback                                 |
|------------|------------------|------------------------------------------|
| `gguf`     | `gguf_backend`   | `#[cfg(not(feature = "gguf"))]` in lib.rs uses `MockSlmBackend` |
| `cloud`    | `cloud_backend`  | Module absent when disabled; no code references it unconditionally |
| `download` | `downloader`     | Module absent when disabled; `model_manager::download()` also gated |

The `MockSlmBackend` in `engine.rs` is always compiled (no cfg gate), ensuring
the SLM crate works correctly with zero features enabled.

## Build verification

All of the following pass:

```
cargo check -p clawdefender-slm                                    # no features (mock)
cargo check -p clawdefender-slm --features "gguf,cloud,download"   # all features
cargo check -p clawdefender-daemon                                 # default (gguf)
cargo check -p clawdefender-daemon --features gguf                 # explicit gguf
cargo check -p clawdefender-daemon --no-default-features            # mock backend
cargo check -p clawdefender-cli --features gguf                    # explicit gguf
cargo check --workspace                                            # full workspace
```
