# ClawDefender Cryptographic Keys

This directory holds development signing keys. Production keys must NEVER be committed.

## Key Inventory

### 1. Ed25519 Threat Feed Signing Key

- **Private key**: `keys/dev-feed-signing.key` (PEM, not committed)
- **Public key hex**: `e9b20cb34831fe44c9fa5001b9226d75ab2805ffb576e5186a88a0645c575844`
- **Embedded in**: `crates/clawdefender-threat-intel/src/signature.rs` (EMBEDDED_PUBLIC_KEY_HEX)
- **Used for**: Signing threat feed manifests (Ed25519 via ed25519-dalek)

To sign a feed manifest in CI:

```bash
# Extract raw private key seed (32 bytes) from PEM:
openssl pkey -in keys/dev-feed-signing.key -outform DER | tail -c 32 | xxd -p -c 32
# Use this hex seed with the feed signing tool.
```

For production, generate a fresh keypair and update EMBEDDED_PUBLIC_KEY_HEX.

### 2. Tauri Updater Signing Key

- **Private key**: `keys/tauri-updater.key` (minisign format, not committed)
- **Public key**: `keys/tauri-updater.key.pub` (not committed)
- **Embedded in**: `clients/clawdefender-app/src-tauri/tauri.conf.json` (plugins.updater.pubkey)
- **Used for**: Signing desktop app update bundles

CI environment variables:

```bash
export TAURI_SIGNING_PRIVATE_KEY="$(cat keys/tauri-updater.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""  # empty for dev key
```

### 3. Guard REST API Token

- **Generated at runtime** by the daemon on first start
- **Location**: `~/.local/share/clawdefender/server-token` (mode 0600)
- **Format**: 64 hex characters (256-bit random)
- **Used by**: Guard REST API (`Authorization: Bearer <token>`), MCP server, SDKs

## CI/Production Key Management

| Key | CI Secret Name | Notes |
|-----|---------------|-------|
| Feed signing private key | `FEED_SIGNING_PRIVATE_KEY` | Hex-encoded 32-byte Ed25519 seed |
| Tauri updater private key | `TAURI_SIGNING_PRIVATE_KEY` | Full minisign private key content |
| Tauri updater password | `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Empty for dev, set for production |

For production:
1. Generate fresh keypairs (do not reuse dev keys)
2. Store private keys in your CI secrets manager (GitHub Actions secrets, etc.)
3. Update the embedded public keys in source code
4. The server-token is auto-generated per installation and should not be shared
