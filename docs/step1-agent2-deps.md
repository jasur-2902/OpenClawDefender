# Step 1 — Dependency Resolution Report

## 1. Unified `dirs` v5 → v6

**Files changed:**
- `crates/clawdefender-guard/Cargo.toml` — `dirs = "5"` → `dirs = "6"`
- `crates/clawdefender-threat-intel/Cargo.toml` — `dirs = "5"` → `dirs = "6"`
- `clients/clawdefender-app/src-tauri/Cargo.toml` — `dirs = "5"` → `dirs = "6"`

**API impact:** None. The `dirs` v5 → v6 upgrade is API-compatible for all functions used in this workspace (`home_dir()`, `config_dir()`, `data_local_dir()`). No source code changes were needed.

**Crates now unified on dirs v6:** clawdefender-guard, clawdefender-threat-intel, clawdefender-app, clawdefender-mcp-server.

## 2. Unified `rand` v0.8 → v0.9

**Files changed:**
- `crates/clawdefender-scanner/Cargo.toml` — `rand = "0.8"` → `rand = "0.9"`
- `crates/clawdefender-scanner/src/modules/fuzzing.rs` — renamed all `gen_range()` calls to `random_range()` (5 occurrences)

**API changes applied:**
- `Rng::gen_range()` was deprecated in rand 0.9 and renamed to `Rng::random_range()`.
- `StdRng`, `SeedableRng`, and `Rng` imports remain unchanged.

**Not upgraded:** `crates/clawdefender-threat-intel/Cargo.toml` retains `rand = "0.8"` in `[dev-dependencies]` because it is used exclusively with `ed25519-dalek` v2 which depends on `rand_core` 0.6.x (incompatible with rand 0.9's `rand_core` 0.9.x). Upgrading would break `SigningKey::generate(&mut OsRng)` in tests.

## 3. Cleaned up unused import

**File changed:**
- `crates/clawdefender-slm/src/model_manager.rs`
  - Removed `bail` from the top-level import: `use anyhow::{bail, Result}` → `use anyhow::Result`
  - Added `use anyhow::bail;` inside the `#[cfg(feature = "download")]` function body where it is actually used, keeping it compilable with and without the `download` feature.

## 4. Build verification

- `cargo update` — resolved all dependency versions successfully.
- `cargo check --workspace` — **0 errors, 0 warnings**.
