# ClawDefender V1 Release Notes

## What is ClawDefender?

ClawDefender is a firewall for AI agents. It intercepts, inspects, and controls what AI tools can do on your machine by sitting between MCP (Model Context Protocol) clients and servers.

When an AI agent asks to read a file, execute a command, or access a resource via MCP, ClawDefender evaluates the request against your policy rules before it reaches the server. Blocked requests never execute. Prompted requests wait for your explicit approval.

## V1 Features

### MCP Proxy

- **Stdio proxy:** Wraps local MCP servers as a transparent man-in-the-middle. The MCP client thinks it is talking directly to the server.
- **HTTP reverse proxy:** Forwards requests to remote MCP servers after policy evaluation.
- **Message classification:** Incoming JSON-RPC messages are classified as pass-through (handshake, pings), log-only (listings, notifications), or review (tool calls, resource reads, sampling requests).

### Policy Engine

- **TOML-based rules:** Define allow, block, prompt, or log actions per tool name, resource path, method, or event type.
- **Glob and regex patterns:** Match tool names and paths using glob (`shell_*`, `/project/**`) or regex patterns.
- **First-match-wins evaluation:** Rules are ordered by priority. The first matching rule determines the action.
- **Session rules:** Users can create temporary allow rules during a session (e.g., "allow this tool for the rest of this session").
- **Persistent rules:** Rules can be written to disk via the TUI and persist across sessions.
- **Path canonicalization:** All resource paths are canonicalized before matching to prevent path traversal bypasses.

### Terminal TUI

- **Real-time event feed:** See every intercepted MCP message as it flows through the proxy.
- **Interactive prompts:** When a tool call triggers a `prompt` rule, the TUI presents options: allow once, deny, allow for session, or add to permanent policy.
- **Keyboard-driven:** Navigate with arrow keys, respond to prompts with single keystrokes.

### Audit System

- **Structured JSONL logging:** Every intercepted message, policy decision, and user response is logged.
- **Query interface:** `clawdefender log` supports filtering by action, server, time range, and tool name.
- **Aggregate statistics:** `clawdefender log --stats` shows summary counts of allowed, blocked, and prompted events.
- **Log rotation:** Automatic rotation by file size with configurable retention.

### CLI

- `clawdefender init` -- Generate a default policy file.
- `clawdefender wrap <server>` -- Rewrite MCP client config to route through ClawDefender.
- `clawdefender unwrap <server>` -- Restore original MCP client config.
- `clawdefender tui` -- Launch the interactive terminal UI.
- `clawdefender log` -- Query the audit log.
- `clawdefender policy test` -- Test policy rules against fixture files.

### Security Hardening

- **Path canonicalization:** Prevents `../../etc/passwd`-style traversal in policy matching.
- **Prompt rate limiting:** Auto-blocks servers that trigger more than 10 prompts in 60 seconds.
- **Parser limits:** 10 MB max message size, 128-level max JSON depth, 20 MB buffer overflow protection.
- **ReDoS protection:** Regex patterns have a 256 KB compiled size limit.

## What is NOT included in V1

- **OS-level monitoring (eslogger):** The `eslogger` sensor crate exists but is not integrated into the V1 proxy flow. It will be connected in Phase 2.
- **On-device SLM analysis:** Small language model analysis of tool call intent is planned for Phase 2.
- **Multi-agent swarm coordination:** The `clawdefender-swarm` crate is a placeholder for Phase 2+ work.
- **Windows/Linux OS monitoring:** OS-level monitoring is macOS-only. The proxy and policy engine are cross-platform.

## Known Limitations

- **Case sensitivity on macOS:** The policy engine's glob matching is case-sensitive, but macOS HFS+/APFS is case-insensitive by default. A path rule for `/Users/alice/project/**` will not match `/users/alice/project/file.txt` even though the filesystem treats them as the same path.
- **No argument-level matching in V1:** Policy rules match on tool name, resource path, method, and event type. Matching on specific argument values within a tool call (e.g., "block `shell_exec` only when the `cmd` argument contains `rm`") is planned for a future release.
- **Prompt timeout defaults to 30 seconds:** If the user does not respond to a prompt within 30 seconds, the request is denied. This is configurable but may surprise new users.
- **eslogger requires elevated permissions:** OS monitoring via `eslogger` requires root or Full Disk Access on macOS. This is not required for the MCP proxy functionality.

## How to Install

```bash
# Install script
curl -sSL https://clawdefender.dev/install.sh | sh

# Homebrew
brew install clawdefender

# From source
git clone https://github.com/clawdefender/clawdefender.git
cd clawdefender && cargo build --release
```

## How to Get Started

```bash
clawdefender init
clawdefender wrap filesystem-server
# Restart your MCP client (Claude Desktop, Cursor)
clawdefender tui
```

## Reporting Issues

File issues at: https://github.com/clawdefender/clawdefender/issues

Include the output of `clawdefender --version` and relevant sections of `clawdefender log` when reporting bugs.
