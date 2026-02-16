# SLM Guide

ClawDefender includes an on-device Small Language Model (SLM) that provides
AI-powered risk analysis for tool calls intercepted by the proxy.

## Overview

When enabled, the SLM analyzes events that hit `prompt` policy rules and
assigns a risk level (LOW / MEDIUM / HIGH / CRITICAL) with an explanation.
Results appear in the TUI and audit log as additional context.

The SLM is **advisory only** -- it does not block actions on its own. Policy
rules remain the enforcement mechanism.

## Requirements

- A GGUF-format language model file (quantized, typically 1-4 GB)
- Sufficient disk space for the model
- macOS with Metal GPU support (optional, for faster inference)

## Installation

### Download a recommended model

```bash
clawdefender model download
```

This downloads the default recommended model to
`~/.local/share/clawdefender/models/`.

### List available and installed models

```bash
clawdefender model list
```

### Manual installation

Place any GGUF model file in the models directory:

```bash
mkdir -p ~/.local/share/clawdefender/models
cp /path/to/your-model.gguf ~/.local/share/clawdefender/models/
```

## Configuration

The SLM is configured in `~/.config/clawdefender/clawdefender.toml`:

```toml
[slm]
enabled = true
model_path = "~/.local/share/clawdefender/models/default.gguf"
context_size = 2048        # Context window in tokens
max_output_tokens = 256    # Max tokens per inference
temperature = 0.1          # Lower = more deterministic
threads = 4                # CPU threads for inference
use_gpu = true             # Metal acceleration on macOS
batch_size = 512           # Prompt evaluation batch size
```

### Toggle on/off

```bash
clawdefender model toggle on
clawdefender model toggle off
```

### View statistics

```bash
clawdefender model stats
```

Shows total inferences, average latency, token usage, and GPU status.

## How it works

### Analysis pipeline

1. **Event arrives** -- A tool call or resource read hits a `prompt` policy rule.
2. **Noise filter** -- Benign developer activity (compilers, git, IDEs, test
   runners, package managers) is automatically suppressed without SLM analysis.
3. **Input sanitization** -- Untrusted data from MCP arguments is sanitized to
   remove prompt injection patterns.
4. **Random delimiter wrapping** -- Sanitized data is wrapped in tags with a
   unique random nonce to prevent delimiter escape attacks.
5. **Prompt construction** -- A security-focused prompt is built with the event
   details, server context, and reputation data.
6. **SLM inference** -- The local GGUF model runs inference (serialized, one at
   a time, with a queue of up to 10 pending requests).
7. **Output validation** -- The response is checked for echo attacks, injection
   artifacts, and structural validity.
8. **Canary verification** -- A verification token embedded in the system prompt
   must appear in the response.
9. **Result** -- The risk assessment is attached to the audit record and
   displayed in the TUI.

### Noise filter profiles

The noise filter suppresses common developer activity to reduce SLM overhead:

| Profile          | Examples                                        |
|------------------|-------------------------------------------------|
| Compiler/Build   | gcc, clang, rustc, cargo build, make, ninja     |
| Git              | git status, diff, log, commit, push             |
| IDE/LSP          | rust-analyzer, copilot, language servers         |
| Test Runners     | cargo test, pytest, jest, npm test, go test      |
| Package Managers | npm install, pip install, cargo install, brew    |

Custom noise rules can be added in `~/.config/clawdefender/noise.toml`.

### Security hardening

The SLM analysis pipeline includes multiple defenses against prompt injection:

- **Input sanitization**: Strips injection patterns, XML tags, and output format
  mimicry from untrusted data
- **Random nonce delimiters**: Unpredictable tags prevent delimiter escape
- **Output validation**: Detects echo attacks, instruction leakage, and role
  assumption in model output
- **Canary tokens**: Verification tokens confirm the response was not hijacked
- **Advisory-only**: SLM results never override policy enforcement decisions

See [Threat Model](threat-model.md) for a detailed analysis of prompt injection
attacks and defenses.

## Troubleshooting

### SLM shows as disabled

Check that:
1. The model file exists at the configured path
2. `enabled = true` is set in the `[slm]` section of `clawdefender.toml`
3. Run `clawdefender model list` to verify the model is installed

### High latency

- Enable GPU acceleration: set `use_gpu = true` in config
- Reduce `context_size` or `max_output_tokens`
- Use a smaller quantized model (Q4 instead of Q8)
- Check `clawdefender model stats` for average latency

### Too many events reaching SLM

- The noise filter should handle most benign activity automatically
- Add custom rules to `~/.config/clawdefender/noise.toml` for your workflow
- Check `clawdefender model stats` to see inference counts

### Model download fails

- Check network connectivity
- Verify disk space in `~/.local/share/clawdefender/models/`
- Try manual download and placement (see Installation section)
