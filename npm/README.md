# Rookbot

A firewall for AI agents — intercept, inspect, and control MCP tool calls.

## Install

```bash
npm install -g rookbot
```

Or via Homebrew:

```bash
brew install rookbot/tap/rookbot
```

Or via curl:

```bash
curl -fsSL https://raw.githubusercontent.com/rookbot-io/rookbot/main/scripts/install.sh | bash
```

## Quick Start

```bash
# Initialize configuration
rookbot init

# Protect an MCP server
rookbot wrap <server-name>

# Check status
rookbot status

# Full usage
rookbot --help
```

## Supported Platforms

| Platform | Architecture | Status |
|----------|-------------|--------|
| macOS    | arm64 (Apple Silicon) | Supported |
| macOS    | x86_64 (Intel) | Supported |
| Linux    | x86_64 | Supported |
| Linux    | arm64/aarch64 | Supported |

## License

Apache-2.0 OR MIT
