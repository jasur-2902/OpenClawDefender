# ClawDefender v0.7.0 Release Notes

## Overview

ClawDefender v0.7.0 introduces an **autonomous behavioral defense engine** that learns per-server behavioral baselines and detects anomalies, multi-step attack patterns, and prompt injection attempts in real time. This is a major security upgrade that moves ClawDefender from purely rule-based defense to adaptive, behavior-aware protection.

## New Features

### Behavioral Baselines

ClawDefender now automatically builds behavioral profiles for each MCP server by observing tool calls, file access patterns, network connections, and temporal behavior during a configurable learning phase. After learning, any deviation from the established baseline generates anomaly scores.

### Anomaly Detection (9 Dimensions)

Events are scored across 9 dimensions:

- **UnknownTool** -- tool never or rarely seen during learning
- **UnknownPath** -- file access outside known directory territory
- **UnknownNetwork** -- connection to unknown host or port
- **AbnormalRate** -- request rate significantly above baseline
- **AbnormalSequence** -- tool call sequence never observed
- **AbnormalArguments** -- tool called with novel argument keys
- **SensitiveTarget** -- access to credential files (SSH keys, AWS credentials, etc.)
- **FirstNetworkAccess** -- previously non-networked server making connections
- **PrivilegeEscalation** -- indicators of privilege escalation

The floor rule ensures that any dimension scoring 1.0 produces a minimum total of 0.7.

### Kill Chain Recognition (6 Patterns)

Multi-step attack detection recognizes sequences of events that form known attack patterns:

1. **Credential theft + exfiltration** (Critical) -- credential read then network connect
2. **Reconnaissance + credential access** (High) -- directory listing then credential read
3. **Persistence installation** (Critical) -- write to startup location then shell exec
4. **Data staging + exfiltration** (Critical) -- multiple credential reads, /tmp write, network connect
5. **Shell escape** (High) -- tool call immediately followed by shell execution
6. **Prompt injection followthrough** (High) -- sampling response followed by shell execution

Kill chain matches add a +0.3 boost to the anomaly score.

### Auto-Block (Opt-In)

When enabled, events exceeding the auto-block threshold (default 0.9) are automatically blocked without user intervention. Auto-block is **OFF by default** -- it must be explicitly enabled in configuration.

A feedback loop tracks the override rate: if users override more than 10% of auto-blocks (after 10+ blocks), ClawDefender recommends raising the threshold.

### Prompt Injection Detection

A dedicated injection detection engine scans MCP sampling messages with 24 built-in regex patterns and Aho-Corasick multi-pattern matching across 5 categories:

- Instruction overrides
- Role reassignment
- Data exfiltration commands
- Encoded payloads
- System prompt leakage attempts

Response messages are weighted 2x compared to requests. Custom pattern files can be loaded from TOML configuration.

## New CLI Commands

### Behavioral Commands

```bash
clawdefender behavioral status    # Show behavioral engine status and active profiles
clawdefender behavioral calibrate # Run threshold calibration against recent events
clawdefender behavioral stats     # Show auto-block statistics and override rate
```

### Profile Management

```bash
clawdefender profile list         # List all server profiles
clawdefender profile show <name>  # Show detailed profile for a server
clawdefender profile reset <name> # Reset a profile back to learning mode
clawdefender profile export <name># Export profile as JSON
```

## Configuration

### Behavioral Engine

Add to `~/.config/clawdefender/clawdefender.toml`:

```toml
[behavioral]
enabled = true                    # Enable behavioral defense (default: true)
learning_event_threshold = 100    # Events required before learning completes
learning_time_minutes = 30        # Minutes required before learning completes
anomaly_threshold = 0.7           # Score above which warnings are shown
auto_block_threshold = 0.9        # Score above which events are auto-blocked
auto_block_enabled = false        # Auto-block is opt-in (default: false)
```

### Injection Detector

```toml
[injection_detector]
enabled = true                    # Enable injection detection (default: true)
threshold = 0.6                   # Score above which messages are flagged
auto_block = false                # Auto-block flagged messages (default: false)
# patterns_path = "path/to/custom_patterns.toml"  # Optional custom patterns
```

## Security Improvements

- **9 anomaly dimensions** with weighted scoring and floor rule
- **6 kill chain patterns** with configurable time windows
- **24 prompt injection patterns** across 5 heuristic categories
- **Conservative profile updates** using EMA (alpha=0.1) and set expansion threshold (5 observations)
- **Per-server isolation** -- no cross-server contamination in behavioral analysis
- **Feedback loop** -- tracks override rate to prevent overly aggressive blocking

## Known Limitations

Documented evasion gaps are covered in detail in `docs/behavioral-security.md`:

- **Gradual baseline poisoning**: An attacker who slowly introduces anomalous behavior during learning may establish a permissive baseline
- **Path obfuscation**: Symlinks and path traversal may evade directory territory checks
- **Low-and-slow attacks**: Events spread across long time windows may evade kill chain detection
- **Encoding variations**: Novel encoding schemes may bypass injection detector patterns

## Test Coverage

Phase 7 includes comprehensive test coverage with 1,057+ tests:

| Component | Tests |
|-----------|-------|
| Learning engine | 24 |
| Profile persistence | 7 |
| Profile updater (EMA) | 9 |
| Anomaly scorer (9 dimensions) | 30 |
| Kill chain detector (6 patterns) | 34 |
| Injection detector (5 heuristics, 24 patterns) | 39 |
| Decision engine (auto-block) | 23 |
| Security & evasion tests | 31 |
| Daemon integration | 10 |
| Integration test harness (realistic simulation) | 6 |
| End-to-end pipeline tests | 17 |

The integration test harness simulates a realistic filesystem-server session with 500+ normal events followed by a compromise scenario, verifying:
- 0% false positive rate during normal activity
- Detection within the first event of behavioral change
- Correct kill chain detection for credential theft + exfiltration

## Migration

This release is **backward compatible** with Phase 6 configurations. No breaking changes:

- Existing `clawdefender.toml` files continue to work without modification
- The `[behavioral]` and `[injection_detector]` config sections use safe defaults
- Behavioral defense is enabled by default but auto-block is off
- All existing policy rules, audit logs, and CLI commands remain unchanged

## Upgrade Guide

1. Update ClawDefender to v0.7.0.
2. No configuration changes required -- the behavioral engine starts in learning mode automatically.
3. Optionally add `[behavioral]` and `[injection_detector]` sections to your config file.
4. Wait for the learning phase to complete (100 events, 30 minutes by default).
5. Review behavioral warnings in the TUI or audit log.
6. Use `clawdefender behavioral calibrate` to validate thresholds.
7. When satisfied, optionally enable auto-block:
   ```toml
   [behavioral]
   auto_block_enabled = true
   ```
