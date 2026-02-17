# ClawDefender v0.3 - Phase 11 Release Notes

## Threat Intelligence System

Phase 11 introduces a comprehensive threat intelligence subsystem that provides real-time protection against known threats targeting MCP servers.

### New Features

#### Threat Feed Infrastructure
- **Feed client** with automatic background updates every 6 hours
- **Ed25519 signature verification** for feed integrity
- **Local caching** with SHA-256 hash-based change detection
- **Feed format versioning** for forward compatibility

#### Blocklist & Known Malicious Server Registry
- Database of known-malicious, vulnerable, and compromised MCP servers
- **12 initial blocklist entries** covering:
  - 4 malicious servers (credential exfiltration, code injection, keylogging, cryptomining)
  - 5 vulnerable servers (path traversal, SQL injection, command injection, SSRF, DoS)
  - 3 compromised versions (supply chain attacks, typosquatting)
- Severity-based classification (Low/Medium/High/Critical)
- User override mechanism with audit logging

#### Community Rules Engine
- **5 rule packs** with **50 rules** total:
  - **Credential Protection** (12 rules) - SSH, AWS, GCloud, Azure, Kubernetes, GPG, browser credentials, npm/GitHub tokens, Docker
  - **Network Security** (10 rules) - outbound connection control, SSRF prevention, C2 blocking
  - **Persistence Prevention** (10 rules) - LaunchAgents, shell rc files, cron, systemd, sudoers
  - **Privacy Protection** (10 rules) - browser data, email, messages, photos, contacts, calendar, keychain
  - **Filesystem Server Hardened** (8 rules) - optimized rules for the official filesystem MCP server
- Install/uninstall via CLI or GUI
- Rule precedence ordering: User > ThreatIntel > Community > Default

#### IoC Matching Engine
- Real-time matching against **115+ indicators**:
  - 55 malicious host indicators (IPs, CIDR ranges, domains)
  - 25 malicious file hash indicators
  - 35 suspicious tool/command patterns
- Support for IP, domain, URL, file hash, file path, process name, command line, tool sequence, and argument pattern indicators
- CIDR range matching, wildcard domain matching, glob pattern matching
- Confidence scoring with false-positive rate tracking

#### Attack Pattern Updates
- **3 new kill chain patterns**:
  - Supply chain injection (package install + credential read + network exfil)
  - Data staging and exfiltration (temp write + compress + upload)
  - Environment variable exfiltration (env read + network connect)
- **17 injection signatures** including:
  - 8 multilingual patterns (Chinese, Spanish, French, German, Japanese, Korean, Russian, Arabic)
  - 3 XML/HTML tag injection patterns
  - 2 markdown injection patterns
  - 2 code block escape patterns
  - 2 homoglyph attack patterns

#### Behavioral Profiles
- **5 pre-seeded profiles** for official MCP servers:
  - `@modelcontextprotocol/server-filesystem`
  - `@modelcontextprotocol/server-fetch`
  - `@modelcontextprotocol/server-git`
  - `@modelcontextprotocol/server-sqlite`
  - `@anthropic/brave-search-server`
- Expected tools, file territory, network/shell behavior, request rate stats

#### Anonymous Telemetry
- Privacy-preserving threat detection data sharing
- Opt-in via GUI toggle or configuration
- No personal data or file contents transmitted
- Aggregated threat statistics only

### GUI Updates
- New **Threat Intelligence** page in the ClawDefender app
- Feed status display with manual update button
- Blocklist warnings with severity indicators
- Community rule pack browser with install/uninstall
- IoC database statistics
- Telemetry toggle with data preview

### CLI Updates
- `clawdefender feed status` - Check feed status
- `clawdefender feed update` - Force feed update
- `clawdefender blocklist show` - Display blocklist
- `clawdefender blocklist check <server>` - Check server reputation
- `clawdefender blocklist override <id>` - Override a blocklist entry
- `clawdefender rules list` - List available rule packs
- `clawdefender rules install <id>` - Install a rule pack
- `clawdefender rules uninstall <id>` - Uninstall a rule pack
- `clawdefender ioc stats` - Show IoC database statistics
- `clawdefender telemetry status` - Show telemetry status

### Feed Publishing
- GitHub Actions CI/CD pipeline for automated feed publishing
- Feed validation tooling (`validate-feed.py`)
- Feed signing tooling (`sign-feed.py`)
- GitHub Pages deployment

### Testing
- 1,616+ tests passing across the workspace
- GUI vitest tests for threat intel components
- Integration tests for the threat intel pipeline

## Important Notes

- All initial feed data uses safe/reserved IP ranges and synthetic hashes
- The feed is designed for community contribution - see the contributing guide
- Feed updates are automatic but can be disabled in settings
- Telemetry is opt-in and fully transparent about what is collected
