# Behavioral Engine Security Analysis

## Design Philosophy

ClawDefender's behavioral engine follows a **defense-in-depth** approach:

1. **Learning Phase** — Observe normal behavior to build a baseline profile per MCP server
2. **Anomaly Scoring** — Score events against the baseline across 9 dimensions
3. **Kill Chain Detection** — Match multi-step attack patterns within time windows
4. **Prompt Injection Detection** — Regex + Aho-Corasick heuristics for injection patterns
5. **Conservative Updates** — Post-learning profile changes require repeated observations (EMA + threshold)

Key design principles:
- **Auto-block is opt-in** — The `auto_block_enabled` flag defaults to `false`. Anomalous events trigger prompts, not blocks, unless explicitly configured.
- **False positive management** — The floor rule ensures any dimension scoring 1.0 produces a total >= 0.7, while normal operations within established territory score < 0.2.
- **Sensitive paths are always flagged** — Regardless of learned territory, accessing paths like `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, etc. triggers the `SensitiveTarget` dimension at score 1.0.

## What the Engine Can Detect

| Scenario | Detection Method | Confidence |
|----------|-----------------|------------|
| Unknown tool usage | AnomalyScorer::UnknownTool | High |
| File access outside territory | AnomalyScorer::UnknownPath | High |
| Sensitive path access (SSH keys, AWS creds, etc.) | AnomalyScorer::SensitiveTarget | High |
| First-time network access from non-networked server | AnomalyScorer::FirstNetworkAccess | High |
| Unknown network destinations | AnomalyScorer::UnknownNetwork | Medium |
| Abnormal request rate (z-score) | AnomalyScorer::AbnormalRate | Medium |
| Novel tool sequences | AnomalyScorer::AbnormalSequence | Medium |
| Novel argument patterns | AnomalyScorer::AbnormalArguments | Medium |
| Credential theft + exfiltration chain | KillChainDetector (pattern 1) | High |
| Reconnaissance + credential access chain | KillChainDetector (pattern 2) | High |
| Persistence installation | KillChainDetector (pattern 3) | High |
| Data staging + exfiltration chain | KillChainDetector (pattern 4) | High |
| English-language prompt injection | InjectionDetector | Medium-High |
| Encoded payloads (base64, hex, URL) | InjectionDetector | Medium |

## What the Engine Cannot Detect

| Gap | Reason | Mitigation |
|-----|--------|------------|
| Symlink-based path evasion | No path canonicalization/resolution | OS-level symlink resolution before scoring |
| Non-English prompt injection | English-only regex patterns | Add multilingual patterns |
| Unicode homoglyph substitution | Regex matches exact characters | Unicode normalization layer |
| Leetspeak injection | Regex expects standard spelling | Character normalization or fuzzy matching |
| Zero-width character insertion | Invisible chars break word boundaries | Strip zero-width chars before scanning |
| Spaced-out injection text | Regex expects contiguous words | Whitespace normalization |
| Slow-drip attacks exceeding time windows | Fixed window sizes | Longer windows or cumulative scoring |
| Attacks via mounted filesystems | String-based path checking | Integrate with OS file event resolution |
| Base64 payloads under 50 chars | Threshold is 50 chars | Lower threshold or add content-aware decoding |

## Known Evasion Techniques

### 1. Baseline Poisoning

**Attack**: During the learning phase, inject a small percentage of malicious events (e.g., 10% `~/.ssh/` reads) mixed with benign events.

**Result**: The `~/.ssh/` directory gets added to `directory_prefixes`, making it "known territory."

**Mitigation**: The `SensitiveTarget` dimension fires independently of territory. Even if `~/.ssh/` is in the learned territory, accessing sensitive files like `id_rsa` still scores 1.0 on `SensitiveTarget`, triggering the floor rule (total >= 0.7). **Baseline poisoning is mitigated for known sensitive paths.**

**Remaining Risk**: Sensitive paths NOT in the default list can be poisoned into the baseline.

### 2. Path Obfuscation

**Attack**: Use path traversal (`../../`), double slashes (`//`), or dot segments (`./`) to disguise sensitive path access.

**Result**: The anomaly scorer does NOT canonicalize paths. However:
- `contains()`-based sensitive path detection catches traversal paths that still contain patterns like `/.ssh/` or `/id_rsa`
- `starts_with()`-based territory checking may be fooled (e.g., `/home/user/Projects/../../.ssh/id_rsa` starts with `/home/user/Projects`)

**Mitigation**: Add path canonicalization before scoring. For OS events, use resolved paths from the kernel.

### 3. Kill Chain Time Window Evasion

**Attack**: Spread attack steps across time, exceeding the pattern's `window_seconds`.

**Result**: The detector correctly misses out-of-window events. This is by design — the windows are configurable.

**Default windows**:
- Credential theft + exfiltration: 60 seconds
- Reconnaissance + credential access: 120 seconds
- Persistence installation: 30 seconds
- Data staging + exfiltration: 120 seconds
- Shell escape: 10 seconds
- Prompt injection followthrough: 30 seconds

**Mitigation**: Use cumulative risk scoring across longer periods. Consider pattern-specific adaptive windows.

### 4. Injection Detector Evasion

| Technique | Evades Detection? | Details |
|-----------|-------------------|---------|
| French text | Yes | No non-English patterns |
| Unicode homoglyphs | Yes | Cyrillic "i" (U+0456) not matched by `(?i)` |
| Leetspeak | Yes | `1gn0re` does not match `ignore` |
| Base64 (short) | Partial | Under 50-char threshold not caught |
| Spaced characters | Yes | `i g n o r e` breaks word matching |
| Mixed case | No | `(?i)` flag handles case insensitivity |
| Zero-width characters | Yes | Invisible chars between word characters |
| Contextual camouflage | Partial | Config-like text may still trigger patterns |

## Kill Chain Patterns

### Pattern Library

1. **credential_theft_exfiltration** (Critical, 60s) — Credential file read -> external network connection
2. **recon_credential_access** (High, 120s) — Broad directory listing -> credential file read
3. **persistence_installation** (Critical, 30s) — Write to startup location -> shell execution
4. **data_staging_exfiltration** (Critical, 120s) — 3+ credential reads -> /tmp write -> network
5. **shell_escape** (High, 10s) — Tool call -> uncorrelated shell execution
6. **prompt_injection_followthrough** (High, 30s) — Sampling response -> shell execution

### Limitations

- **Cross-server isolation**: Events from different servers are never correlated. An attacker using two colluding servers (one reads credentials, another exfiltrates) will evade pattern matching.
- **Fixed step ordering**: Patterns match steps in strict order. An attacker who exfiltrates first and reads credentials second will not be caught by pattern 1.
- **Window granularity**: The sliding window trims events older than 5 minutes (WINDOW_DURATION_SECS = 300). Events older than this are discarded entirely.

## Injection Detector Pattern Library

### Categories

1. **Instruction Overrides** (severity 0.6-0.8) — "ignore previous instructions", "your actual instructions are", "IMPORTANT: from now on"
2. **Role Reassignment** (severity 0.6) — "you are now", "act as", "pretend to be"
3. **Data Exfiltration** (severity 0.7) — "send to https://", "curl", "save to /tmp", "base64 encode and include"
4. **Encoded Payloads** (severity 0.5) — Long base64 (50+ chars), long hex (40+ chars), URL-encoded sequences (10+ segments)
5. **Tool Invocation** (severity 0.4) — "call the tool", JSON tool_name patterns
6. **System Prompt Leakage** (severity 0.6) — "reveal your system prompt", "what are your hidden instructions"
7. **Delimiter Injection** (severity 0.5) — `<|im_start|>`, `[INST]`, `` ``` ``, `<system>`

### Known Gaps

- No multilingual support
- No Unicode normalization (homoglyphs, zero-width chars)
- No character-level fuzzy matching (leetspeak, spaced text)
- No base64/hex content decoding and inspection
- No contextual analysis (academic discussion vs. actual attack)
- Response direction weighting (2x) helps but can cause false positives for code-generation responses

## Recommendations for Threshold Configuration

### Default Thresholds

| Threshold | Default | Purpose |
|-----------|---------|---------|
| `anomaly_threshold` | 0.7 | Alert/prompt the user |
| `auto_block_threshold` | 0.9 | Automatically block the action |
| `injection_threshold` | 0.6 | Flag message for review |
| `learning_event_threshold` | 100 | Events before learning completes |
| `learning_time_minutes` | 30 | Minutes before learning completes |
| `set_expansion_threshold` | 5 | Observations before new entry added post-learning |

### Tuning Recommendations

**For high-security environments**:
- Lower `anomaly_threshold` to 0.5
- Enable `auto_block_enabled`
- Keep `auto_block_threshold` at 0.9 to avoid false positive blocks
- Increase `learning_event_threshold` to 500 and `learning_time_minutes` to 120

**For development/testing environments**:
- Keep `anomaly_threshold` at 0.7
- Disable `auto_block_enabled`
- Lower `learning_event_threshold` to 50 for faster onboarding

**For production with mixed workloads**:
- Use per-server threshold overrides if supported
- Monitor false positive rates and adjust `anomaly_threshold` accordingly
- Consider adding frequently-accessed sensitive paths (like `~/.ssh/config`) to an allowlist
- Set `set_expansion_threshold` to 10+ to make baseline harder to poison

## Security Test Summary

The security test suite (`tests/behavioral_security_tests.rs`) covers:

- **Baseline poisoning** (2 tests): Verifies sensitive path detection survives 10% and 50% poisoning
- **Path obfuscation** (4 tests): Traversal, double slashes, dots, symlinks
- **Kill chain evasion** (5 tests): Window boundaries, slow-drip attacks
- **Injection evasion** (8 tests): French, homoglyphs, leetspeak, base64, spacing, mixed case, zero-width, contextual
- **False positives** (7 tests): SSH config, refactoring, sibling dirs, academic text, normal ops, known network, learning mode
- **Combined scenarios** (2 tests): Full credential theft, multi-dimensional anomaly
- **Edge cases** (2 tests): Empty profile, floor rule verification

Documented findings are annotated in test output with `FINDING` and `NOTE` prefixes.
