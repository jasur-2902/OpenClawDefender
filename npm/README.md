# Rookbot

**A firewall for AI agents.** Intercept, inspect, and control every MCP tool call — before it touches your system.

## Install

```bash
npm install -g rookbot
```

## Quick Start

```bash
rookbot init                    # Initialize config
rookbot daemon start            # Start background daemon
rookbot model download qwen3-1.7b  # Download AI model
rookbot model on                # Enable AI analysis
rookbot wrap --all              # Protect all MCP servers
```

Restart your MCP client (Claude Desktop, Cursor) — done.

## Other Install Methods

```bash
# Homebrew
brew install rookbot-io/tap/rookbot

# Shell script
curl -fsSL https://raw.githubusercontent.com/rookbot-io/rookbot/main/scripts/install.sh | bash
```

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| macOS | Apple Silicon (arm64) |
| macOS | Intel (x86_64) |
| Linux | x86_64 |
| Linux | arm64 / aarch64 |

## Links

- [Documentation](https://github.com/rookbot-io/rookbot)
- [Report a bug](https://github.com/rookbot-io/rookbot/issues)

## License

MIT
