# ClawDefender Threat Feed

This repository contains the threat intelligence feed for ClawDefender, providing blocklists, community rule packs, attack patterns, IoC indicators, and behavioral profiles for MCP server security.

## Structure

```
feed/v1/
  manifest.json            - Feed manifest with file hashes
  blocklist.json           - Known malicious/vulnerable MCP servers
  rules/                   - Community rule packs
  patterns/                - Kill chain and injection signature patterns
  iocs/                    - Indicators of compromise
  profiles/                - Behavioral profiles for known MCP servers
  signatures/              - Feed signature files
```

## Feed URL

The feed is published at:
```
https://feed.clawdefender.io/v1/
```

## Tools

- `tools/sign-feed.py` - Sign the feed manifest with Ed25519
- `tools/validate-feed.py` - Validate all feed JSON files
- `tools/publish-feed.sh` - Publish the feed to GitHub Pages

## Quick Start

```bash
# Validate the feed
python3 tools/validate-feed.py

# Generate a signing key
python3 tools/sign-feed.py --generate-key

# Sign the feed
python3 tools/sign-feed.py --key feed-private.key

# Publish (dry run)
./tools/publish-feed.sh --dry-run
```

## Contributing

See [docs/contributing-threat-intel.md](../docs/contributing-threat-intel.md) for the contributor guide.

## Content Summary

| Category | Count |
|----------|-------|
| Blocklist entries | 12 |
| Rule packs | 5 (50 rules total) |
| Kill chain patterns | 3 |
| Injection signatures | 17 |
| Malicious host indicators | 55 |
| Malicious hash indicators | 25 |
| Suspicious tool patterns | 35 |
| Behavioral profiles | 5 |

**Total IoC indicators: 115+**

## Important Notes

- All synthetic/test entries are clearly marked with `[SYNTHETIC/TEST]`
- IP addresses use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
- Domains use `.example.com/.example.net/.example.org` (RFC 2606 reserved)
- File hashes are synthetic (clearly patterned) and do not correspond to real malware
