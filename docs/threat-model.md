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

## Attack surface of ClawAI itself

### JSON-RPC parser
ClawAI parses untrusted JSON-RPC messages from both the MCP client and server. Bugs here could cause crashes, incorrect routing, or policy bypasses. Mitigation: strict parsing with `serde_json`, extensive fuzz testing.

### Policy engine
The policy evaluation logic must be correct — a bug here is a security bypass. Mitigation: simple rule format (TOML, not a Turing-complete language), comprehensive test suite, property-based testing.

### eslogger JSON parser
`eslogger` outputs JSON events. Malformed or adversarial output (unlikely from a system tool, but possible if the system is partially compromised) could cause parsing failures. Mitigation: lenient parsing that skips malformed events rather than crashing.

### Configuration files
`policy.toml` and `clawai.toml` are read from disk. If an attacker gains write access to these files, they can disable protections. Mitigation: ClawAI warns if policy files have overly permissive filesystem permissions.
