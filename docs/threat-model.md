# Threat Model

## What ClawAI protects against

### Malicious MCP tool calls
An AI agent (or a prompt injection controlling one) attempts to call tools that the user has not authorized. Examples: reading `~/.ssh/id_rsa`, executing `rm -rf /`, writing to `/etc/hosts`. ClawAI's policy engine evaluates every `tools/call` request and blocks those that violate the configured rules.

### Data exfiltration via MCP
An agent reads sensitive data through one tool and exfiltrates it through another (e.g., reads a file, then sends its contents via a network tool). ClawAI can enforce policies that restrict which tools can be combined and what argument patterns are allowed. The audit log records the full sequence for forensic review.

### Prompt injection via sampling
If an MCP server uses the `sampling/createMessage` method to ask the client to generate text, a compromised server could inject instructions into the prompt. ClawAI intercepts sampling requests and can enforce policies on their content.

### Agents operating outside declared MCP tools
An agent might use a `shell/execute` tool to run arbitrary commands not covered by its declared tool set. The OS-level monitor (`eslogger`) observes the actual system calls and the correlation engine flags discrepancies between what was declared via MCP and what actually happened.

## What ClawAI does NOT protect against

### Pre-compromised system
If the operating system is already compromised (rootkit, kernel exploit), ClawAI's observations cannot be trusted. ClawAI assumes a healthy OS.

### Malicious MCP clients
ClawAI sits between client and server. It trusts the client. If the MCP client itself is malicious, it can bypass ClawAI entirely by communicating with servers directly or modifying ClawAI's configuration.

### Kernel-level attacks
ClawAI operates in userspace. It cannot detect or prevent kernel exploits, rootkits, or attacks that operate below the OS event layer.

### Non-MCP attack vectors
If an attacker compromises the system through means other than MCP (SSH brute force, browser exploit, physical access), ClawAI provides no protection. It is specifically a firewall for the MCP protocol.

### Supply chain attacks on MCP servers
If an MCP server itself is backdoored, ClawAI can restrict what it does but cannot detect that its responses contain manipulated data. Garbage in, garbage out.

## Assumptions

1. **The MCP client is trusted.** The user chose to run it, and it faithfully forwards ClawAI's decisions.
2. **The operating system is not compromised.** `eslogger` output is accurate. Process trees are reliable.
3. **The user reviews interactive prompts.** When ClawAI asks "allow this tool call?", the user reads and makes an informed decision.
4. **Policy files are protected by filesystem permissions.** If an attacker can modify `policy.toml`, they can allow anything.

## V1 security mitigations

### Symlink and path traversal attacks
An attacker-controlled MCP server could request resources using path traversal sequences (e.g., `/project/data/../../../etc/passwd`) to bypass policy rules that only allow access to `/project/**`. ClawAI canonicalizes all resource paths before policy evaluation using a stack-based algorithm that resolves `.` and `..` segments without requiring the target file to exist. Null bytes in paths are rejected outright. This ensures that a policy rule for `/project/**` cannot be bypassed via traversal.

### Prompt fatigue attacks
A malicious MCP server could flood the user with prompt-triggering tool calls, hoping the user starts blindly clicking "Allow" out of frustration. ClawAI implements per-server prompt rate limiting: if a server triggers more than 10 prompts within a 60-second window, all further prompts from that server are auto-blocked for the remainder of the session. The user is notified and can explicitly unblock the server if desired.

### Parser safety
ClawAI enforces multiple layers of protection on the JSON-RPC parser:

- **Maximum message size (10 MB):** Single messages exceeding this limit are rejected before parsing.
- **Maximum JSON nesting depth (128 levels):** A pre-parse bracket-counting check prevents stack overflow from deeply nested payloads.
- **Buffer overflow protection (20 MB):** If the streaming parser accumulates more than 20 MB without encountering a newline delimiter, the buffer is cleared to prevent memory exhaustion.
- **Malformed message recovery:** Invalid JSON lines are logged and skipped; the parser continues processing subsequent messages.

### ReDoS protection
Policy rules support regex patterns for matching tool names and paths. The regex engine uses `regex::RegexBuilder` with a compiled size limit (256 KB) to prevent Regular Expression Denial of Service (ReDoS) attacks via pathological patterns. The Rust `regex` crate uses a finite automaton engine that guarantees linear-time matching, providing an additional layer of protection.

### Plaintext traffic visibility
ClawAI sees all MCP traffic in plaintext. The stdio proxy sits between the MCP client and server with full visibility into every JSON-RPC message, including tool call arguments and response data. This is by design -- it is required for policy evaluation and audit logging. Users should be aware that ClawAI's audit logs may contain sensitive data passed through MCP tool calls.

## Attack surface of ClawAI itself

### JSON-RPC parser
ClawAI parses untrusted JSON-RPC messages from both the MCP client and server. Bugs here could cause crashes, incorrect routing, or policy bypasses. Mitigation: strict parsing with `serde_json`, message size limits, JSON depth limits, buffer overflow protection, and extensive fuzz testing.

### Policy engine
The policy evaluation logic must be correct -- a bug here is a security bypass. Mitigation: simple rule format (TOML, not a Turing-complete language), path canonicalization before matching, regex size limits, comprehensive test suite including security-focused integration tests.

### eslogger JSON parser
`eslogger` outputs JSON events. Malformed or adversarial output (unlikely from a system tool, but possible if the system is partially compromised) could cause parsing failures. Mitigation: lenient parsing that skips malformed events rather than crashing.

### Configuration files
`policy.toml` and `clawai.toml` are read from disk. If an attacker gains write access to these files, they can disable protections. Mitigation: ClawAI warns if policy files have overly permissive filesystem permissions.
