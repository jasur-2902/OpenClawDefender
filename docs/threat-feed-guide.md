# Threat Feed Contribution Guide

The ClawDefender threat feed provides blocklists, indicators of compromise (IoCs), kill-chain patterns, injection signatures, and tool profiles. This guide explains how to contribute new entries and keep the feed up to date.

## Feed Structure

The feed lives under `threat-feed/feed/v1/` with this layout:

```
threat-feed/feed/v1/
  manifest.json          # Signed manifest with version, timestamp, checksums
  blocklist.json         # Package/server blocklist entries
  iocs/                  # Indicator of Compromise files
  patterns/              # Kill-chain and injection patterns
  profiles/              # MCP server behavioral profiles
  rules/                 # Community rule packs
  signatures/            # Injection detection signatures
```

## Adding Blocklist Entries

Edit `threat-feed/feed/v1/blocklist.json`. Each entry requires:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier, e.g. `"BL-2025-0042"` |
| `name` | string | Package or server name |
| `type` | string | One of `"npm_package"`, `"pypi_package"`, `"mcp_server"`, `"binary"` |
| `severity` | string | `"critical"`, `"high"`, `"medium"`, or `"low"` |
| `reason` | string | Why it is blocklisted |
| `source` | string | Reference URL (CVE, advisory, blog post) |
| `versions_affected` | string | Semver range, e.g. `"<2.1.0"` or `"*"` |
| `sha256` | string | (Optional) SHA-256 hash of the malicious artifact |
| `date_added` | string | ISO 8601 date, e.g. `"2025-06-15"` |

Example:

```json
{
  "id": "BL-2025-0042",
  "name": "evil-mcp-server",
  "type": "mcp_server",
  "severity": "critical",
  "reason": "Exfiltrates environment variables to external endpoint",
  "source": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
  "versions_affected": "*",
  "date_added": "2025-06-15"
}
```

## Adding IoC Indicators

Create or edit JSON files under `threat-feed/feed/v1/iocs/`. Supported indicator types:

- **ip** — exact IP address or CIDR range
- **domain** — exact domain or wildcard (e.g. `*.evil.com`)
- **hash** — SHA-256 hash of a malicious file
- **file_path** — glob pattern for suspicious file paths
- **process_name** — process name to flag
- **command_line** — regex matching suspicious command lines
- **tool_sequence** — ordered sequence of tool calls indicating an attack

Each indicator needs:

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier |
| `type` | string | Indicator type (see above) |
| `value` | string | The indicator value |
| `threat_id` | string | Related threat identifier |
| `confidence` | float | 0.0 to 1.0 |
| `expires` | string | (Optional) ISO 8601 expiration date |

## Adding Patterns

### Kill-chain patterns

Edit files under `threat-feed/feed/v1/patterns/`. Each kill-chain pattern describes a multi-stage attack sequence. Stages can be of type `bare`, `file_read`, `network`, or other recognized stage types.

### Injection signatures

Edit files under `threat-feed/feed/v1/signatures/`. Injection signatures use regex patterns to detect prompt injection, homoglyph attacks, and XML tag injection in tool arguments.

All regex patterns must be valid Rust regex syntax. Invalid patterns are rejected at load time.

## Signing the Feed After Updates

After modifying any feed file, the manifest must be re-signed:

1. Update `threat-feed/feed/v1/manifest.json` with:
   - New `version` number (increment)
   - Updated `timestamp` (ISO 8601)
   - Recomputed checksums for all changed files

2. Sign the manifest using the Ed25519 signing key:
   ```bash
   # The signing key is available in CI as CLAWDEFENDER_FEED_SIGNING_KEY
   # For local development, use the test signing key
   clawdefender-tools sign-feed threat-feed/feed/v1/manifest.json
   ```

3. The signature is stored in the `signature` field of `manifest.json`.

## Review Process

1. Open a pull request with your feed changes.
2. The CI pipeline validates:
   - JSON syntax is correct
   - All required fields are present
   - Regex patterns compile successfully
   - No duplicate IDs
   - Blocklist entries have valid source URLs
3. A maintainer reviews the content for accuracy and relevance.
4. After merge, the release workflow re-signs the feed and publishes it.

## Guidelines

- Always include a `source` URL pointing to the original advisory, CVE, or analysis.
- Use conservative `confidence` scores: 0.9+ only for confirmed malicious indicators.
- Set `expires` on time-sensitive indicators (e.g., C2 IPs that rotate frequently).
- Do not include synthetic or test data in the production feed.
- Prefer specific indicators over broad patterns to minimize false positives.
