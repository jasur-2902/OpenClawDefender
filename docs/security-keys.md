# Security Key Management Guide

ClawDefender uses multiple cryptographic keys to protect feed integrity, application updates, and API access. This document describes where each key lives, how to rotate them, and what to do if one is compromised.

## Key Inventory

| Key | Purpose | Public location | Private location |
|-----|---------|-----------------|------------------|
| Ed25519 feed signing key | Signs threat feed manifests | Embedded in `crates/clawdefender-threat-intel/src/signature.rs` (`EMBEDDED_PUBLIC_KEY_HEX`) | CI secret `CLAWDEFENDER_FEED_SIGNING_KEY` |
| Tauri updater signing key | Signs desktop application updates | Embedded in `clients/clawdefender-app/src-tauri/tauri.conf.json` (`plugins.updater.pubkey`) | CI secret `TAURI_SIGNING_PRIVATE_KEY` |
| Guard API token | Authenticates local HTTP clients to the MCP guard server | Generated on first start, stored at `~/.local/share/clawdefender/server-token` | Same file (local only) |

## Ed25519 Feed Signing Key

### How it works

Every threat feed manifest is signed with an Ed25519 private key. The corresponding public key is compiled into the binary so that ClawDefender can verify feed authenticity without any network trust.

### Where the keys live

- **Public key (hex):** `crates/clawdefender-threat-intel/src/signature.rs`, constant `EMBEDDED_PUBLIC_KEY_HEX`.
- **Private key:** stored as the CI/CD secret `CLAWDEFENDER_FEED_SIGNING_KEY`. Never committed to the repository.

### Rotation procedure

1. Generate a new Ed25519 keypair (e.g. using the `clawdefender-keygen` helper or `openssl`).
2. Update `EMBEDDED_PUBLIC_KEY_HEX` in `signature.rs` with the new public key hex.
3. Use the `FeedVerifier::set_next_key()` / `rotate()` mechanism to announce the new key in a manifest signed with the old key, giving clients a transition period.
4. Update the `CLAWDEFENDER_FEED_SIGNING_KEY` CI secret with the new private key.
5. Re-sign the feed with the new key.
6. After one release cycle, remove the old key from the `next_key` slot.

### Compromise response

If the private signing key is leaked:

1. Immediately generate a new keypair.
2. Publish an emergency feed update signed with the old key that includes the new public key in the `next_public_key` field.
3. Release a new binary with the updated `EMBEDDED_PUBLIC_KEY_HEX`.
4. Revoke the old CI secret and replace it with the new private key.
5. Re-sign all feed artifacts with the new key.

## Tauri Updater Signing Key

### How it works

Desktop application updates distributed through GitHub Releases are signed with a minisign-compatible key. The Tauri updater plugin verifies the signature before applying any update.

### Where the keys live

- **Public key:** `clients/clawdefender-app/src-tauri/tauri.conf.json`, field `plugins.updater.pubkey`.
- **Private key:** CI secret `TAURI_SIGNING_PRIVATE_KEY`, used by the Tauri build pipeline.

### Rotation procedure

1. Generate a new minisign keypair: `tauri signer generate`.
2. Update `pubkey` in `tauri.conf.json` with the new public key.
3. Update `TAURI_SIGNING_PRIVATE_KEY` in CI with the new private key.
4. Publish a release signed with the **old** key that updates users to a version containing the **new** public key.
5. All subsequent releases use the new key.

### Compromise response

1. Generate a new keypair immediately.
2. Push one final release signed with the old key whose sole purpose is to embed the new public key.
3. Revoke the old CI secret.
4. All future releases use the new key.

## Guard API Token

### How it works

The MCP guard HTTP server requires a bearer token for all API requests. This prevents unauthorized local processes from interacting with the guard.

### Lifecycle

1. On first start, if no token file exists at `~/.local/share/clawdefender/server-token`, the daemon generates a cryptographically random 32-byte hex token and writes it there.
2. The CLI and Tauri app read this file to authenticate API calls.
3. The token is validated using constant-time comparison to prevent timing attacks.

### Rotation

To rotate the Guard API token:

1. Stop the ClawDefender daemon.
2. Delete `~/.local/share/clawdefender/server-token`.
3. Restart the daemon. A new token is generated automatically.
4. Any external integrations that cached the old token will need the new value.

### Security notes

- The token file should be readable only by the user (`chmod 600`).
- The token never leaves the local machine.
- Empty or missing bearer tokens are always rejected with HTTP 401.

## General Key Safety Rules

- Private keys must **never** be committed to the repository.
- The `keys/.gitignore` excludes `*.key`, `*.secret`, `*.pem`, and `*.p8`.
- All CI secrets should have restricted access (e.g. only the release workflow can read signing keys).
- Audit CI secret access logs periodically.
