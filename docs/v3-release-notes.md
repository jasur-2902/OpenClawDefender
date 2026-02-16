# v0.3.0 Release Notes

## What's new

### Cloud-Powered Deep Analysis (Swarm)

ClawDefender v0.3.0 introduces a multi-agent swarm that escalates ambiguous or high-risk events to cloud LLMs for deeper analysis. When the local SLM flags an event above a configurable threshold, three specialist agents analyze it in parallel:

- **Hawk**: Network security and data exfiltration detection
- **Forensics**: Command and code forensics (obfuscation, privilege escalation, persistence mechanisms)
- **Internal Affairs**: Prompt injection and agent intent analysis

The Commander synthesizes their findings into a final verdict with risk level, explanation, recommended action, and confidence score.

### Bring Your Own Key (BYOK)

API keys are stored securely in the macOS Keychain. ClawDefender auto-detects the provider from the key prefix and supports Anthropic, OpenAI, and custom OpenAI-compatible endpoints. Keys never touch disk or logs.

### Budget Controls

Hard daily and monthly spending caps prevent runaway API costs. Token usage and costs are tracked per-specialist in a local SQLite database. When budgets are exhausted, swarm analysis pauses automatically.

### Chat UI

A new web-based chat interface lets you investigate flagged events with follow-up questions. Start the server with `clawdefender chat serve` and interact through the REST API or browser. Conversation history is stored locally in SQLite.

### Data Minimization

Before sending event data to cloud providers, ClawDefender strips known secret patterns (API keys, tokens, passwords, SSH keys, JWTs, emails, home directory paths) and replaces them with redacted placeholders.

### Output Sanitization

Cloud LLM responses are checked for prompt injection artifacts including nonce echoes, URLs, code blocks, and instruction override patterns. Flagged responses are downweighted during verdict synthesis.

### Audit Chain Hashing

Swarm analysis records are linked with SHA-256 chain hashing for tamper-evident audit trails.

## New crate: clawdefender-swarm

| Module | Purpose |
|--------|---------|
| `keychain` | Secure API key storage (macOS Keychain + in-memory fallback) |
| `llm_client` | Unified LLM client for Anthropic and OpenAI with retry logic |
| `prompts` | Specialist prompt construction with nonce-based injection hardening |
| `commander` | Parallel dispatch to 3 specialists and rule-based synthesis |
| `cost` | Token tracking, budget enforcement, usage SQLite database |
| `chat` | Conversation manager for follow-up questions |
| `chat_server` | Axum web server for chat REST API |
| `data_minimizer` | PII/secret stripping before cloud upload |
| `output_sanitizer` | Injection detection in specialist responses |
| `audit_hasher` | SHA-256 chain hashing for audit records |

## New CLI commands

- `clawdefender chat setup` -- Store API key in Keychain
- `clawdefender chat serve` -- Start the chat web server
- `clawdefender chat sessions` -- List chat sessions
- `clawdefender chat usage` -- Show token usage and costs

## Configuration

Add to `~/.config/clawdefender/clawdefender.toml`:

```toml
[swarm]
enabled = true
escalation_threshold = "MEDIUM"
daily_budget_usd = 1.00
monthly_budget_usd = 20.00
```

## Upgrading from v0.2.0

1. Run `cargo build --release` or install the new binary
2. Run `clawdefender chat setup` to configure your API key (optional)
3. Add the `[swarm]` section to your `clawdefender.toml` (optional)
4. Restart the daemon: `clawdefender daemon restart`

No breaking changes to existing configuration. The swarm is disabled by default and all v0.2.0 features continue to work unchanged. The local SLM remains the primary analysis engine; the swarm is an optional escalation path.
