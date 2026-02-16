# Swarm Analysis Guide

ClawDefender's swarm analysis provides cloud-powered deep analysis for events that the local SLM flags as ambiguous or high-risk. It uses a Bring Your Own Key (BYOK) model -- you provide your own API key, and all API calls go directly from your machine to the LLM provider.

## Setup

### 1. Store your API key

```bash
clawdefender chat setup
```

This stores your API key in the macOS Keychain. ClawDefender auto-detects the provider from the key prefix:

- `sk-ant-*` -- Anthropic
- `sk-*` -- OpenAI

You can also configure a custom provider with any OpenAI-compatible API endpoint.

### 2. Configure escalation

Edit `~/.config/clawdefender/clawdefender.toml`:

```toml
[swarm]
enabled = true
escalation_threshold = "MEDIUM"   # LOW, MEDIUM, HIGH, or CRITICAL
daily_budget_usd = 1.00
monthly_budget_usd = 20.00
```

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable/disable swarm analysis | `false` |
| `escalation_threshold` | Minimum SLM risk level to trigger escalation | `MEDIUM` |
| `daily_budget_usd` | Maximum daily spend on API calls | `1.00` |
| `monthly_budget_usd` | Maximum monthly spend on API calls | `20.00` |

### 3. Restart the daemon

```bash
clawdefender daemon restart
```

## How it works

When the local SLM flags an event at or above the escalation threshold:

1. **Data minimization**: Secrets, PII, and sensitive patterns are stripped from the event data
2. **Parallel dispatch**: Three specialist agents analyze the event simultaneously:
   - **Hawk** -- Network security & data exfiltration detection
   - **Forensics** -- Command & code forensics (obfuscation, privilege escalation, persistence)
   - **Internal Affairs** -- Prompt injection & intent analysis
3. **Output sanitization**: Each specialist's response is checked for injection artifacts
4. **Synthesis**: The Commander merges the three reports into a final verdict
5. **Cost tracking**: Token counts and estimated costs are recorded

## Interpreting verdicts

The swarm produces a `SwarmVerdict` with:

| Field | Description |
|-------|-------------|
| `risk_level` | CRITICAL, HIGH, MEDIUM, or LOW |
| `explanation` | Top findings from the specialists |
| `recommended_action` | `block`, `investigate`, or `allow` |
| `confidence` | 0.0 to 1.0 (lower when specialists time out or return garbage) |

**Synthesis rules:**
- If ANY specialist says CRITICAL, the final verdict is CRITICAL
- If 2+ specialists say HIGH, the final verdict is HIGH
- If only 1 says HIGH (dissent), the verdict is downgraded to MEDIUM
- Otherwise, the median risk level is used

## Chat UI

The chat UI lets you ask follow-up questions about flagged events.

### Start the server

```bash
clawdefender chat serve
```

This starts an Axum web server on `http://localhost:3000` with endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/sessions` | GET | List chat sessions |
| `/api/sessions` | POST | Create a new session for an event |
| `/api/sessions/:id/messages` | GET | Get messages in a session |
| `/api/sessions/:id/messages` | POST | Send a message and get a response |

### List sessions

```bash
clawdefender chat sessions
```

### Monitor usage

```bash
clawdefender chat usage
```

Shows token counts, estimated costs, and budget remaining for the current period.

## Budget management

ClawDefender enforces hard spending caps:

- **Daily budget**: Resets at midnight UTC each day
- **Monthly budget**: Resets on the 1st of each month

When a budget is exhausted, swarm analysis is automatically disabled until the next period. The local SLM continues to operate normally.

To check current usage:

```bash
clawdefender chat usage
```

## Troubleshooting

### "No API key configured"

Run `clawdefender chat setup` to store your API key. Verify with:

```bash
clawdefender chat status
```

### "Budget exhausted"

Your daily or monthly spending cap has been reached. Either wait for the next period or increase the budget in `clawdefender.toml`.

### Specialist timeouts

If specialists do not respond within 10 seconds, ClawDefender uses fallback responses (MEDIUM risk, 0.5 confidence). This can happen during API outages or rate limiting. The verdict will have lower confidence to reflect the missing data.

### High costs

Each swarm analysis makes 3 API calls. To reduce costs:
- Raise the `escalation_threshold` to only escalate high-risk events
- Lower `daily_budget_usd` to set a hard cap
- Use a less expensive model (configurable in future versions)

### Injection artifacts in specialist responses

If you see warnings about flagged specialist responses, this means ClawDefender's output sanitizer detected potential prompt injection in the cloud LLM's response. The flagged response is downweighted during synthesis. This is a safety feature working as intended.
