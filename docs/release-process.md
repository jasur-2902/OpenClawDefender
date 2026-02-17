# ClawDefender Release Process

## Prerequisites

- Rust toolchain with `aarch64-apple-darwin` and `x86_64-apple-darwin` targets
- `just` command runner installed
- Write access to the GitHub repository
- All tests passing (`just preflight`)

## Version Bumping

1. Update the version in `Cargo.toml` (workspace-level `[workspace.package]`):

   ```bash
   just bump-version 0.2.0
   ```

2. Update `Formula/clawdefender.rb` version field.

3. Run `cargo check --workspace` to regenerate `Cargo.lock`.

4. Commit the version bump:

   ```bash
   git add Cargo.toml Cargo.lock Formula/clawdefender.rb
   git commit -m "chore: bump version to 0.2.0"
   ```

## Release Steps

1. **Run preflight checks:**

   ```bash
   just preflight
   ```

2. **Tag the release:**

   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin main --tags
   ```

3. **GitHub Actions will automatically:**
   - Build universal binaries (aarch64 + x86_64) for both `clawdefender` and `clawdefender-daemon`
   - Create a `lipo` universal binary
   - Ad-hoc code sign the binaries
   - Create a tarball with SHA-256 checksum
   - Publish a GitHub Release with auto-generated release notes

4. **Post-release: Update Homebrew formula:**

   After the release is published, download the tarball and compute its SHA-256:

   ```bash
   curl -fsSL https://github.com/clawdefender/clawdefender/releases/download/v0.2.0/clawdefender-macos-universal.tar.gz -o /tmp/clawdefender.tar.gz
   shasum -a 256 /tmp/clawdefender.tar.gz
   ```

   Update the `sha256` field in `Formula/clawdefender.rb` with the actual hash.

## Files That Need Version Updates

| File | Field |
|------|-------|
| `Cargo.toml` | `[workspace.package] version` |
| `Formula/clawdefender.rb` | `version` and `sha256` |

## Local Testing

To build and install locally without a release:

```bash
just install-local
```

To create a local package:

```bash
just package
```

## Release Artifacts

Each release produces:

- `clawdefender-macos-universal.tar.gz` -- Universal binary tarball containing:
  - `clawdefender` (CLI)
  - `clawdefender-daemon` (background daemon)
- `clawdefender-macos-universal.tar.gz.sha256` -- SHA-256 checksum

## Apple Code Signing (Future)

When Apple Developer ID certificates are configured:

1. Set the following GitHub secrets:
   - `APPLE_CERTIFICATE_P12`
   - `APPLE_CERTIFICATE_PASSWORD`
   - `APPLE_TEAM_NAME`
   - `APPLE_ID`
   - `APPLE_APP_PASSWORD`
   - `APPLE_TEAM_ID`

2. Uncomment the signing and notarization steps in `.github/workflows/release.yml`.
