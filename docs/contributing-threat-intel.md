# Contributing to ClawDefender Threat Intelligence

Thank you for your interest in contributing to the ClawDefender threat feed. This guide explains how to submit new threat data, rule packs, and behavioral profiles.

## Types of Contributions

### 1. Blocklist Entries

Report malicious, vulnerable, or compromised MCP servers.

**Required information:**
- Server name and npm package (if applicable)
- Entry type: `MaliciousServer`, `VulnerableServer`, or `CompromisedVersion`
- Severity: `Low`, `Medium`, `High`, or `Critical`
- Description of the threat
- Affected versions (for vulnerable/compromised entries)
- Indicators of compromise (network destinations, file access patterns, behavior)
- Remediation steps
- References (advisory URLs, CVEs)

**Template:**
```json
{
  "id": "CLAW-YYYY-NNN",
  "entry_type": "VulnerableServer",
  "name": "package-name",
  "versions_affected": "<1.2.3",
  "versions_fixed": ["1.2.3"],
  "severity": "High",
  "description": "Clear description of the vulnerability.",
  "discovery_date": "2026-01-01",
  "indicators": {
    "network": [],
    "file_access": [],
    "behavior": "Description of observable malicious behavior."
  },
  "remediation": "Steps to remediate the issue.",
  "references": ["https://example.com/advisory"],
  "npm_package": "package-name",
  "cve": "CVE-YYYY-NNNNN"
}
```

### 2. Community Rule Packs

Create reusable security policy rule packs.

**Requirements:**
- Unique pack ID
- Category: `Security`, `Privacy`, `Development`, `ServerSpecific`, or `FrameworkSpecific`
- 5-15 rules per pack
- Each rule must have: name, action, methods, paths, message, tags

**Rule actions:**
- `block` - Block the operation silently
- `prompt` - Ask user for approval
- `allow` - Explicitly allow
- `log` - Allow but audit

### 3. IoC Indicators

Submit indicators of compromise in these categories:

- **Malicious hosts** - IP addresses/ranges or domain names
- **File hashes** - SHA-256 hashes of known-malicious files
- **Suspicious tools** - Command patterns or tool sequences

**Important:** Use documentation/reserved ranges for test data:
- IPs: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737)
- Domains: .example.com, .example.net, .example.org (RFC 2606)

### 4. Kill Chain Patterns

Define multi-step attack patterns with:
- Unique ID (format: `KC-FEED-NNN`)
- Ordered steps with event types and path/destination patterns
- Time window in seconds
- Severity level

### 5. Injection Signatures

Submit prompt injection detection patterns:
- Unique ID (format: `INJ-FEED-NNN`)
- Regex pattern
- Severity weight (0.0 - 1.0)
- Language tag (for multilingual patterns)

### 6. Behavioral Profiles

Define expected behavior for MCP servers:
- Server package name
- Expected tools list
- Network/shell expectations
- Request rate statistics

## Submission Process

1. Fork the repository
2. Create a branch: `feed/add-<description>`
3. Add your contribution to the appropriate file in `threat-feed/feed/v1/`
4. Run validation: `python3 threat-feed/tools/validate-feed.py`
5. Submit a pull request with:
   - Description of the threat/rule
   - Evidence or references
   - Testing methodology

## Quality Guidelines

- All entries must have clear, accurate descriptions
- Synthetic/test data must be clearly marked with `[SYNTHETIC/TEST]`
- Use reserved IP ranges and example domains for test data
- Include remediation steps for all blocklist entries
- Rule packs should have descriptive messages for each rule
- IoC indicators should include confidence levels when possible
- Kill chain patterns should have realistic time windows

## Review Process

Submissions are reviewed for:
1. **Accuracy** - Is the threat real and correctly described?
2. **Completeness** - Are all required fields present?
3. **Safety** - Does test data use reserved ranges?
4. **Quality** - Are descriptions clear and actionable?
5. **Validation** - Does the feed validate successfully?

## Code of Conduct

- Only submit verified threat intelligence
- Do not submit data that could be used for malicious purposes
- Respect responsible disclosure timelines
- Credit original researchers when applicable

## Questions

Open an issue with the `threat-intel` label for questions about contributing.
