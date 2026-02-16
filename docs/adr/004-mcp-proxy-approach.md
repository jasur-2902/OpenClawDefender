# ADR-004: MCP Proxy Approach

**Status:** Accepted

## Context

ClawAI needs to intercept MCP communication between clients and servers to enforce security policies. We needed to decide *how* to intercept this communication.

MCP supports two transport mechanisms:
1. **stdio** — the client spawns the server as a child process and communicates over stdin/stdout.
2. **HTTP with SSE** — the client connects to the server over HTTP, with server-sent events for streaming.

## Decision

For stdio-based MCP servers, ClawAI operates as a **man-in-the-middle on stdio**: the MCP client spawns ClawAI instead of the real server, and ClawAI spawns the real server as its own child process, relaying messages in both directions after policy evaluation.

For HTTP-based MCP servers, ClawAI operates as an **HTTP reverse proxy**: the client connects to ClawAI's local HTTP endpoint, and ClawAI forwards requests to the real server after policy evaluation.

### Rationale

**stdio MITM is transparent and requires no server modification.** The MCP client doesn't know ClawAI exists — it just sees a process that speaks the MCP protocol. The MCP server doesn't know either — it just reads from stdin and writes to stdout as usual. This means ClawAI works with *any* MCP server without changes.

**HTTP reverse proxy is the standard pattern for HTTP interception.** Well-understood, well-tested, and allows reuse of existing HTTP middleware for logging, rate limiting, etc.

**Configuration is a one-line change.** `clawai wrap` modifies the MCP client config to launch `clawai proxy -- <original-command>` instead of the original command. One line, fully reversible.

### Rejected alternatives

**Kernel-level interception (Endpoint Security, eBPF).** Maximum visibility but extreme complexity. Requires entitlements (macOS) or root (Linux). Blocks open-source contribution (see ADR-006). Would intercept *all* system calls, not just MCP — massive noise, difficult to correlate.

**LD_PRELOAD / DYLD_INSERT_LIBRARIES.** Library injection to intercept I/O calls. On macOS, System Integrity Protection (SIP) prevents this for system binaries and signed applications. Most MCP servers run under Node.js or Python, which are often SIP-protected. Unreliable and platform-fragile.

**Modifying MCP clients.** Adding interception directly into Claude Desktop, Cursor, etc. Requires cooperation from every client vendor, is unmaintainable across versions, and defeats the purpose of an independent security layer.

**Network-level proxy (mitmproxy-style).** Only works for HTTP transport. stdio-based MCP servers don't touch the network at all. Would miss the majority of current MCP usage.

## Consequences

- ClawAI must correctly handle the full JSON-RPC protocol, including notifications, batches, and edge cases. Bugs in the relay could break MCP functionality.
- Process management (spawning, monitoring, and reaping the child server process) adds complexity. ClawAI must handle server crashes, slow starts, and clean shutdown.
- The stdio MITM approach means ClawAI adds latency to every message. Measured overhead target: <1ms per message for policy evaluation.
