# Version Management Guide

ClawDefender maintains a single version number across all crates, configuration files, and distribution packages. This document describes how versions are managed and released.

## Current Version

**0.5.0-beta**

## The `just bump-version` Command

The project includes a `just` recipe that updates the version everywhere in one step:

```bash
just bump-version 0.6.0-beta
```

This command updates all of the following locations automatically:

| File | Field |
|------|-------|
| `Cargo.toml` (workspace root) | `version` — drives all workspace member crates |
| `clients/clawdefender-app/src-tauri/Cargo.toml` | `version` (excluded from workspace) |
| `tests/mock-mcp-server/Cargo.toml` | `version` |
| `tests/mock-eslogger/Cargo.toml` | `version` |
| `clients/clawdefender-app/src-tauri/tauri.conf.json` | `version` |
| `clients/clawdefender-app/package.json` | `version` (via `npm version`) |
| `Formula/clawdefender.rb` | `version` (Homebrew formula) |
| `Homebrew/clawdefender-app.rb` | `version` (Homebrew cask) |
| `extensions/clawdefender-network/Info.plist` | `CFBundleShortVersionString` |
| `sdks/typescript-agent/package.json` | `version` |
| `sdks/python-agent/pyproject.toml` | `version` |

## Versioning Scheme

ClawDefender follows semantic versioning with pre-release tags:

- **Major.Minor.Patch** for stable releases (e.g. `1.0.0`)
- **Major.Minor.Patch-tag** for pre-releases (e.g. `0.5.0-beta`, `1.0.0-rc1`)

## Release Process

1. **Bump the version:**
   ```bash
   just bump-version X.Y.Z
   ```

2. **Run the full test suite:**
   ```bash
   just test
   ```

3. **Commit the version bump:**
   ```bash
   git add -A
   git commit -m "release: vX.Y.Z"
   ```

4. **Tag the release:**
   ```bash
   git tag vX.Y.Z
   git push origin main --tags
   ```

5. **CI handles the rest:**
   - Builds release binaries for macOS (arm64 + x86_64)
   - Builds the Tauri desktop app and signs it
   - Publishes to GitHub Releases
   - Updates the Homebrew tap
   - Signs and publishes the updated threat feed

## Verifying Version Consistency

To check that all locations are in sync:

```bash
# Workspace Cargo.toml
grep '^version' Cargo.toml

# Tauri config
grep '"version"' clients/clawdefender-app/src-tauri/tauri.conf.json

# Frontend package.json
grep '"version"' clients/clawdefender-app/package.json
```

All should report the same version string.

## Notes

- The `fuzz/Cargo.toml` intentionally uses version `0.0.0` and is not bumped.
- The workspace `Cargo.toml` version propagates to all workspace member crates via `workspace = true` inheritance — individual crate `Cargo.toml` files do not need separate version fields.
