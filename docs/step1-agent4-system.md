# Agent 4: System & Platform Engineering Report

## Summary

All workspace crates build successfully in release mode on macOS (Apple Silicon). No system or platform errors. One significant finding regarding Metal GPU acceleration being unconfigured.

---

## 1. llama_cpp Build Configuration

**Status: BUILDS, BUT METAL GPU NOT ENABLED**

### What works
- `llama_cpp` v0.3.2 compiles successfully via the `cc` crate (not CMake)
- `llama_cpp_sys` uses bundled llama.cpp source compiled with `cc::Build`
- The `gguf` feature is correctly gated behind `#[cfg(feature = "gguf")]` in `clawdefender-slm`
- When the model file is missing or loading fails, the service falls back to disabled mode gracefully
- Security: symlink check on model paths prevents path traversal attacks

### Metal GPU issue
The `llama_cpp` crate's default features enable `native` which includes `compat`, `avx`, `avx2`, `fma`, `f16c`, and `accel`. These are Intel SIMD features. **Metal GPU support requires the explicit `metal` feature flag**, which is NOT enabled anywhere in the workspace.

Current dependency chain:
```
clawdefender-slm [features = ["gguf"]]
  -> llama_cpp v0.3.2 [default features: compat, native]
     -> llama_cpp_sys [features: compat, native, avx, avx2, fma, f16c, accel]
        (NO metal feature)
```

The code in `gguf_backend.rs:67` sets `params.n_gpu_layers = u32::MAX` when `config.use_gpu` is true, but without the Metal feature compiled in, this is a no-op -- all inference runs on CPU only.

**Recommended fix** (not applied -- requires team discussion):
```toml
# In crates/clawdefender-slm/Cargo.toml:
llama_cpp = { version = "0.3", optional = true, features = ["metal"] }
```
This would enable Metal GPU acceleration on macOS. On non-macOS platforms, Metal compilation would be skipped by the `llama_cpp_sys` build.rs (`cfg!(target_os = "macos")` gate).

### No build.rs
There is no `build.rs` in `crates/clawdefender-slm/`. The llama.cpp compilation is handled entirely by `llama_cpp_sys`'s own build script.

---

## 2. macOS Framework Dependencies

**Status: ALL FRAMEWORKS PROVIDED BY THE OS**

Verified via `otool -L` on release binaries:

| Framework | Used By | Binary |
|-----------|---------|--------|
| CoreFoundation | Rust runtime, networking | daemon, CLI |
| Security | rustls TLS stack | daemon, CLI |
| SystemConfiguration | DNS resolution | daemon, CLI |
| IOKit | System info queries | daemon only |
| CoreServices | FSEvents filesystem watcher | daemon only |
| libc++ | llama.cpp C++ runtime | CLI |
| libobjc | Objective-C runtime | daemon |

No `#[link(name = "framework")]` directives found in the Rust source -- all framework linking comes from upstream crates (ring, rustls, notify, sysinfo).

No explicit references to Security.framework, SystemConfiguration, or IOKit in the project's own source code. These are pulled in transitively by dependencies.

---

## 3. eslogger Handling

**Status: ROBUST, HANDLES ALL EDGE CASES**

The sensor crate (`crates/clawdefender-sensor/src/eslogger/process.rs`) handles eslogger availability comprehensively:

### Pre-flight checks
1. **macOS version check**: `check_macos_version()` runs `sw_vers -productVersion` and verifies >= 13.0
2. **Binary existence**: `check_eslogger_binary()` verifies `/usr/bin/eslogger` exists
3. **Full Disk Access**: `check_fda()` tests by reading `~/Library/Mail` (TCC-protected path)
4. **FDA instructions**: Human-readable setup guide via `fda_instructions()`

### Runtime resilience
- **Crash recovery**: Exponential backoff (2s initial, 60s max, resets after 300s of stability)
- **Stale detection**: Restarts if no events received for 30s while process is alive
- **Graceful shutdown**: SIGTERM with 3s grace period, then SIGKILL
- **Channel overflow**: Drops events with periodic logging when channel is full (10,000 capacity)
- **Cross-platform**: `#[cfg(not(target_os = "macos"))]` stub returns a clear error

### Non-macOS / older macOS
- Compiles on all platforms (stub implementation for non-macOS)
- The SensorManager starts the filesystem watcher regardless; eslogger is optional
- macOS < 13 gets a clear error message: "macOS X.Y is not supported. eslogger requires macOS 13.0 (Ventura) or later."

---

## 4. Release Build Verification

**Status: BOTH BINARIES BUILD AND LINK SUCCESSFULLY**

```
cargo build --release -p clawdefender-daemon  -> OK (48.04s)
cargo build --release -p clawdefender-cli     -> OK (57.95s)
```

### Binary sizes (Apple Silicon, stripped)
- `clawdefender-daemon`: 5.5 MB
- `clawdefender` (CLI): 5.3 MB

### Warnings (non-blocking)
1. **Unused import**: `bail` in `crates/clawdefender-slm/src/model_manager.rs:5` (1 warning)
2. **Deprecated method**: `rand::Rng::gen_range` renamed to `random_range` in `crates/clawdefender-scanner/src/modules/fuzzing.rs` (5 warnings)

### Release profile
Fat LTO, single codegen unit, stripped symbols, size-optimized (`opt-level = "z"`), abort on panic. This is aggressive but appropriate for a security tool where binary size and performance matter.

No LTO errors, no linker issues, no symbol conflicts between llama.cpp and the rest of the codebase.

---

## 5. System Requirements Summary

Created `/Users/jasur/workspace/clawai/SYSTEM-REQUIREMENTS.md` with full documentation.

### Minimum requirements
- macOS 13.0+ (Ventura) for full functionality
- Xcode Command Line Tools (provides C/C++ compiler)
- Rust stable toolchain (tested: 1.93.1)
- **CMake is NOT required** (llama_cpp_sys uses cc crate)

### Architecture notes
- Apple Silicon (arm64): Primary target, fully supported
- Intel (x86_64): Supported, gets AVX/AVX2/FMA SIMD optimizations
- Metal GPU: Not currently compiled in (see finding #1 above)

---

## Action Items

| Priority | Item | Status |
|----------|------|--------|
| Medium | Enable `metal` feature for `llama_cpp` to get GPU acceleration | Not applied (needs team discussion) |
| Low | Fix unused `bail` import in model_manager.rs | Reported to team |
| Low | Update `gen_range` to `random_range` in scanner fuzzing module | Reported to team |
