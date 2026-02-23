# Security Policy

## Security Mechanisms

ClawDefender employs multiple layers of security:

### Ed25519 Feed Signing
All threat feed manifests are signed with an Ed25519 key. The public key is compiled into the binary (`EMBEDDED_PUBLIC_KEY_HEX` in `crates/clawdefender-threat-intel/src/signature.rs`). The feed verifier supports key rotation via `next_public_key` fields in manifests, allowing seamless transitions without breaking existing installations.

### Guard API Authentication
The MCP guard HTTP server requires a bearer token for all requests. The token is a cryptographically random 32-byte hex string generated on first start and stored at `~/.local/share/clawdefender/server-token`. Token validation uses constant-time comparison to prevent timing side-channel attacks. Empty or missing tokens are always rejected with HTTP 401.

### Model Checksum Verification
All curated GGUF model downloads are verified against SHA-256 checksums embedded in the model catalog (`crates/clawdefender-slm/src/model_registry.rs`). This ensures model files have not been tampered with during download or at rest.

### Tauri Update Signing
Desktop application updates are signed with a minisign-compatible key. The Tauri updater plugin verifies the signature before applying any update. The public key is embedded in `tauri.conf.json`.

### Additional Protections
- Written in Rust to eliminate memory safety vulnerabilities.
- Minimal dependencies, audited with `cargo-audit` and `cargo-deny`.
- Policy engine is deliberately simple to reduce attack surface.
- eslogger integration is read-only observation; ClawDefender never injects into other processes.
- CSP headers restrict the Tauri webview to same-origin and localhost connections.

## Threat Model

### What ClawDefender protects against
- **Malicious MCP servers** — detects and blocks known-bad servers, packages, and tool call patterns via the signed threat feed.
- **Supply chain attacks** — blocklist entries cover malicious npm/PyPI packages with version-aware matching.
- **Prompt injection** — multi-language injection detection with homoglyph, XML tag, and regex-based signature matching.
- **Kill-chain attacks** — detects multi-stage attack sequences (recon, exfiltration, lateral movement) across tool calls.
- **Unauthorized local access** — Guard API token prevents rogue local processes from controlling the daemon.
- **Tampered updates** — signed feed manifests and signed app updates prevent supply-chain attacks on ClawDefender itself.

### What ClawDefender does NOT protect against
- A pre-compromised operating system (ClawDefender assumes the OS kernel is trustworthy).
- Vulnerabilities within MCP servers themselves (report those to server maintainers).
- Vulnerabilities within MCP clients (report those to client maintainers).
- Network-level attacks (the Network Extension is not yet integrated into the main binary).

## Reporting a Vulnerability

If you discover a security vulnerability in ClawDefender, please report it responsibly.

**Preferred:** [GitHub private vulnerability report](https://github.com/clawdefender/clawdefender/security/advisories/new)

**Alternative:** Email [security@clawdefender.dev](mailto:security@clawdefender.dev)

Do not open a public issue for security vulnerabilities.

## Scope

The following are in scope for security reports:

- **Policy bypasses** — tool calls that should be blocked by a policy rule but are allowed through.
- **JSON-RPC parser bugs** — malformed input that causes crashes, hangs, or incorrect routing.
- **Privilege escalation** — any way ClawDefender itself can be used to gain elevated access.
- **Audit log tampering** — circumventing or falsifying audit records.
- **Configuration injection** — manipulating policy files or ClawDefender configuration through crafted MCP messages.
- **Feed signature bypass** — any way to get ClawDefender to accept an unsigned or incorrectly signed feed.
- **Token bypass** — any way to access the Guard API without a valid token.

## Out of Scope

- Vulnerabilities in MCP servers themselves (report those to the server maintainers).
- Vulnerabilities in MCP clients (report those to the client maintainers).
- Issues that require a pre-compromised system (ClawDefender assumes the OS is not already compromised).
- Denial of service via resource exhaustion (we will fix these, but they are low severity for a local tool).

## Response Timeline

| Stage | Timeline |
|---|---|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix for critical issues | Within 7 days |
| Fix for non-critical issues | Within 30 days |
| Public disclosure | After fix is released, coordinated with reporter |

## Key Management

For detailed information on key storage, rotation, and compromise response, see [docs/security-keys.md](docs/security-keys.md).
