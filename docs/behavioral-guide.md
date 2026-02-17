# ClawDefender Behavioral Defense Guide

This guide explains how ClawDefender's autonomous behavioral defense engine works and how to configure it for your environment.

## How the Behavioral Engine Learns Baselines

When ClawDefender first observes an MCP server, it enters a **learning phase**. During this phase:

- Every event (tool calls, file access, network connections) updates the server's behavioral profile directly.
- **No anomaly scores are generated** -- all events pass through without warnings.
- Learning ends only when **both** thresholds are met:
  - **Event threshold**: At least 100 events observed (configurable via `learning_event_threshold`).
  - **Time threshold**: At least 30 minutes elapsed since first observation (configurable via `learning_time_minutes`).

After learning completes, the profile switches to **active mode**. In active mode, profiles continue to update incrementally using exponential moving averages (EMA) and conservative set expansion, but anomaly scores are now generated for every event.

### What the Profile Captures

Each server profile tracks four behavioral dimensions:

| Dimension | What It Tracks |
|---|---|
| **Tool Profile** | Tool call frequencies, argument patterns, tool sequence bigrams |
| **File Profile** | Directory territory (known paths), file extension distribution, read/write ratio |
| **Network Profile** | Known hosts and ports, whether the server has ever made network connections |
| **Temporal Profile** | Inter-request gap statistics (mean, stddev), session duration |

## How to Interpret Anomaly Scores

Every event after learning produces an anomaly score between 0.0 and 1.0, composed of up to 9 dimensions:

| Dimension | Weight | What It Detects |
|---|---|---|
| **UnknownTool** | 0.30 | Tool never or rarely seen during learning |
| **UnknownPath** | 0.40 | File access outside known directory territory |
| **UnknownNetwork** | 0.50 | Connection to unknown host/port |
| **AbnormalRate** | 0.20 | Request rate significantly above baseline (z-score > 2) |
| **AbnormalSequence** | 0.15 | Tool call sequence never observed in bigrams |
| **AbnormalArguments** | 0.15 | Tool called with novel argument keys |
| **SensitiveTarget** | 0.30 | Access to sensitive paths (SSH keys, AWS credentials, etc.) |
| **FirstNetworkAccess** | 0.50 | Server that never networked now making connections |
| **PrivilegeEscalation** | varies | Indicators of privilege escalation |

The composite score is a weighted average across all applicable dimensions.

**Floor rule**: If any single dimension scores 1.0, the total score is at least 0.7 -- ensuring that critical anomalies are never hidden by averaging.

### Score Ranges

| Score Range | Meaning | Default Action |
|---|---|---|
| 0.0 - 0.69 | Normal | Pass through (NormalPrompt) |
| 0.70 - 0.89 | Suspicious | Show warning to user (EnrichedPrompt) |
| 0.90 - 1.0 | Critical | Auto-block if enabled, otherwise EnrichedPrompt |

## How to Enable Auto-Block

Auto-block is **opt-in and OFF by default**. When enabled, events with anomaly scores >= the auto-block threshold are automatically blocked without prompting the user.

To enable auto-block, edit `~/.config/clawdefender/clawdefender.toml`:

```toml
[behavioral]
enabled = true
auto_block_enabled = true
auto_block_threshold = 0.9   # Score above which events are auto-blocked
anomaly_threshold = 0.7       # Score above which warnings are shown
```

### Kill Chain Boost

When a kill chain pattern matches (e.g., credential read followed by network connect), a +0.3 boost is added to the anomaly score. This means an event scoring 0.7 with a kill chain match becomes 1.0, triggering auto-block if enabled.

## How to Calibrate Thresholds

Use the calibrate command to see what would happen at different thresholds based on recent event history:

```bash
clawdefender behavioral calibrate
```

This analyzes recent events and reports:
- How many events would be auto-blocked at thresholds 0.7, 0.8, and 0.9
- Which specific events would be affected

Use this to find the right threshold for your environment before enabling auto-block.

## How to Review Auto-Blocks and Create Trust Rules

When auto-block fires, the event is logged with full audit data including:
- The anomaly score and per-dimension breakdown
- Kill chain pattern matches (if any)
- The server name and event details

Review blocked events:

```bash
clawdefender behavioral stats
```

The engine tracks an **override rate** -- if more than 10% of auto-blocks are overridden by users (after 10+ blocks), ClawDefender recommends raising the threshold. This feedback loop prevents overly aggressive blocking.

## How to Manage Profiles

### List all profiles

```bash
clawdefender profile list
```

Shows all server profiles with their status (learning/active), observation count, and age.

### Show a specific profile

```bash
clawdefender profile show <server-name>
```

Displays detailed profile data including tool frequencies, file territory, network history, and temporal statistics.

### Reset a profile

```bash
clawdefender profile reset <server-name>
```

Resets the profile back to learning mode. Use this when a server's behavior has legitimately changed and you want to re-learn its baseline.

### Export a profile

```bash
clawdefender profile export <server-name>
```

Exports the profile as JSON for backup or analysis.

## Recommended Configuration

### Development (default)

Suitable for most development workflows. Behavioral defense adds warnings without blocking.

```toml
[behavioral]
enabled = true
auto_block_enabled = false
anomaly_threshold = 0.7
learning_event_threshold = 100
learning_time_minutes = 30

[injection_detector]
enabled = true
threshold = 0.6
auto_block = false
```

### Production

For CI/CD pipelines or production environments where MCP servers have predictable behavior.

```toml
[behavioral]
enabled = true
auto_block_enabled = true
auto_block_threshold = 0.9
anomaly_threshold = 0.7
learning_event_threshold = 200
learning_time_minutes = 60

[injection_detector]
enabled = true
threshold = 0.5
auto_block = true
```

### High-Security

For environments handling sensitive data where false negatives are unacceptable.

```toml
[behavioral]
enabled = true
auto_block_enabled = true
auto_block_threshold = 0.8
anomaly_threshold = 0.5
learning_event_threshold = 300
learning_time_minutes = 120

[injection_detector]
enabled = true
threshold = 0.4
auto_block = true
```

## Kill Chain Patterns

ClawDefender ships with 6 built-in attack patterns:

1. **credential_theft_exfiltration** (Critical) -- Credential file read followed by external network connection within 60s.
2. **recon_credential_access** (High) -- Broad directory listing followed by credential file access within 120s.
3. **persistence_installation** (Critical) -- Write to startup location followed by shell execution within 30s.
4. **data_staging_exfiltration** (Critical) -- 3+ credential reads, write to /tmp, then network connect within 120s.
5. **shell_escape** (High) -- Tool call followed immediately by shell execution within 10s.
6. **prompt_injection_followthrough** (High) -- Sampling response followed by shell execution within 30s.

Custom patterns can be added via a TOML file. See `docs/behavioral-security.md` for details.

## Prompt Injection Detection

The injection detector scans MCP sampling messages using 24 built-in regex patterns across 5 categories:

- **Instruction overrides** -- "ignore previous instructions", "your actual instructions are"
- **Role reassignment** -- "you are now", "act as", "pretend to be"
- **Data exfiltration** -- "send to https://", "curl", "save to /tmp"
- **Encoded payloads** -- long base64 strings, hex sequences, URL-encoded data
- **System prompt leakage** -- "reveal your system prompt", "show hidden instructions"

Response messages (LLM -> server) are scored 2x compared to request messages, since injection patterns in responses indicate active exploitation.
