# Certified Servers

MCP servers that have been verified against the ClawDefender compliance
framework. Each server has been tested with `clawdefender certify` and
confirmed to meet the requirements of its stated compliance level.

## Compliance levels

| Level | Name | What it means |
|---|---|---|
| 1 | Aware | Server checks intent before actions |
| 2 | Guarded | Server requests permission before sensitive operations |
| 3 | Certified | Full integration with intent checks, permissions, and audit reporting |

## Certified servers

| Server | Version | Level | Certified | Repository | Notes |
|---|---|---|---|---|---|
| ClawDefender MCP Server | 0.5.0 | 3 | 2026-02 | [clawdefender/clawdefender](https://github.com/clawdefender/clawdefender) | Official ClawDefender MCP server for policy management |
| Example Python Server | 0.1.0 | 3 | 2026-02 | [clawdefender/clawdefender](https://github.com/clawdefender/clawdefender/tree/main/examples/python-mcp-server) | Reference implementation in Python |
| Example TypeScript Server | 0.1.0 | 3 | 2026-02 | [clawdefender/clawdefender](https://github.com/clawdefender/clawdefender/tree/main/examples/typescript-mcp-server) | Reference implementation in TypeScript |

## Submitting your server

To request certification for your MCP server:

1. Integrate the ClawDefender SDK (see [MCP Server Author Guide](mcp-server-author-guide.md))
2. Add a `clawdefender.toml` manifest to your repository root
3. Run `clawdefender certify .` and confirm it passes
4. Open an issue at [github.com/clawdefender/clawdefender](https://github.com/clawdefender/clawdefender/issues)
   with:
   - Server name and repository URL
   - Compliance level
   - Output of `clawdefender certify .`

The ClawDefender team will review your submission and update this list and the
machine-readable `certified-servers.json` file.
