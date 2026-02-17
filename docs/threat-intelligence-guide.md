# ClawDefender Threat Intelligence Guide

## Overview

ClawDefender's threat intelligence system provides real-time protection against known threats targeting MCP (Model Context Protocol) servers. The system downloads and applies threat data from a centralized feed, keeping your installation protected against the latest threats without manual updates.

## Architecture

The threat intelligence system consists of these components:

1. **Threat Feed Client** - Downloads and caches feed data from the remote server
2. **Blocklist Engine** - Identifies and blocks known-malicious MCP servers
3. **Community Rules** - Installable rule packs that define security policies
4. **IoC Matching** - Real-time indicator of compromise detection
5. **Attack Patterns** - Kill chain detection and injection signature scanning
6. **Behavioral Profiles** - Pre-seeded profiles for known MCP server packages
7. **Anonymous Telemetry** - Privacy-preserving threat data sharing (opt-in)

## Feed Configuration

Configure the threat feed in your ClawDefender settings:

```toml
[threat_intel]
enabled = true
feed_url = "https://feed.clawdefender.io/v1/"
update_interval_hours = 6
auto_apply_rules = true
auto_apply_blocklist = true
auto_apply_patterns = true
auto_apply_iocs = true
notify_on_update = true
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable/disable the threat intel subsystem |
| `feed_url` | `https://feed.clawdefender.io/v1/` | Feed base URL |
| `update_interval_hours` | `6` | How often to check for updates |
| `auto_apply_rules` | `true` | Automatically apply downloaded rule packs |
| `auto_apply_blocklist` | `true` | Automatically apply the blocklist |
| `auto_apply_patterns` | `true` | Automatically apply attack patterns |
| `auto_apply_iocs` | `true` | Automatically apply IoC indicators |
| `notify_on_update` | `true` | Show notification when feed is updated |

## Blocklist

The blocklist contains entries for three categories of threats:

- **MaliciousServer** - Servers intentionally designed to be harmful
- **VulnerableServer** - Servers with known security vulnerabilities
- **CompromisedVersion** - Specific versions that have been tampered with (supply chain attacks)

Each entry includes severity (Low/Medium/High/Critical), description, remediation steps, and references.

### Overriding a Blocklist Entry

If you need to use a blocked server despite the warning:

```bash
clawdefender blocklist override <entry-id> --reason "Internal testing" --confirm "I understand the risk"
```

Overrides are logged in the audit trail.

## Community Rule Packs

Rule packs are collections of security rules that can be installed individually:

| Pack | Description |
|------|-------------|
| `credential-protection` | Blocks access to SSH keys, cloud credentials, API tokens |
| `network-security` | Controls outbound connections, blocks malicious destinations |
| `persistence-prevention` | Prevents writes to startup items, shell configs, cron |
| `privacy-protection` | Blocks access to browser data, email, messages, photos |
| `filesystem-server-hardened` | Optimized rules for the official filesystem MCP server |

### Managing Rule Packs

```bash
# List available packs
clawdefender rules list

# Install a pack
clawdefender rules install credential-protection

# Uninstall a pack
clawdefender rules uninstall credential-protection

# Show pack details
clawdefender rules show credential-protection
```

### Rule Actions

Each rule specifies an action:

- **block** - Silently block the operation
- **prompt** - Ask the user for approval
- **allow** - Explicitly allow the operation
- **log** - Allow but log for audit

## IoC (Indicators of Compromise)

The IoC database contains indicators across several categories:

- **Malicious IPs/Domains** - Known-bad network destinations
- **File Hashes** - SHA-256 hashes of known-malicious files
- **Suspicious Tools** - Command patterns associated with attacks
- **Tool Sequences** - Multi-step tool call patterns indicating attack chains

IoCs are matched in real-time against all MCP server activity.

## Attack Patterns

### Kill Chain Detection

Kill chain patterns detect multi-step attacks by correlating events within a time window. For example, the "Supply Chain Injection" pattern detects:

1. Package installation (shell exec)
2. Credential file access (file read)
3. External network connection (network connect)

All occurring within 5 minutes.

### Injection Signatures

Injection signatures detect prompt injection attempts in multiple languages and formats:

- Multilingual instruction overrides (Chinese, Spanish, French, German, Japanese, Korean, Russian, Arabic)
- XML/HTML tag injections (system, instruction, role override tags)
- Markdown injection (hidden comments, invisible text)
- Code block escape attempts
- Homoglyph attacks (Cyrillic/Latin substitution, full-width characters)

## Behavioral Profiles

Pre-seeded profiles define expected behavior for known MCP servers. When a server deviates from its profile, ClawDefender raises an anomaly alert.

Profiles are available for:
- `@modelcontextprotocol/server-filesystem`
- `@modelcontextprotocol/server-fetch`
- `@modelcontextprotocol/server-git`
- `@modelcontextprotocol/server-sqlite`
- `@anthropic/brave-search-server`

## Feed Verification

The threat feed uses Ed25519 signatures for integrity verification. The public key is embedded in the ClawDefender binary. Every feed update is verified before being applied.

## Telemetry

Anonymous telemetry helps improve threat detection by sharing aggregated, privacy-preserving data about detected threats. Telemetry is opt-in and can be toggled in the GUI or via configuration.

No personal data, file contents, or identifying information is ever transmitted.

## GUI

The Threat Intelligence page in the ClawDefender GUI shows:

- **Feed Status** - Current version, last update, next check
- **Blocklist Warnings** - Active blocklist matches for monitored servers
- **Rule Packs** - Available packs with install/uninstall controls
- **IoC Database** - Statistics about loaded indicators
- **Telemetry** - Toggle and preview of telemetry data

## CLI Commands

```bash
# Check feed status
clawdefender feed status

# Force feed update
clawdefender feed update

# Show blocklist
clawdefender blocklist show

# Check a server against the blocklist
clawdefender blocklist check <server-name>

# Show IoC stats
clawdefender ioc stats

# Run a scan
clawdefender scan --server <name>
```

## Troubleshooting

**Feed not updating:**
- Check network connectivity to the feed URL
- Verify `threat_intel.enabled = true` in configuration
- Check daemon logs for feed client errors

**False positives:**
- Use blocklist overrides for known-safe servers
- Adjust rule pack configuration
- Report false positives via the contributing guide

**High anomaly scores:**
- Review behavioral profile expectations
- Check if the server was recently updated
- Allow learning period for custom servers
