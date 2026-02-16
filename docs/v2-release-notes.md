# V2 Release Notes

## What's new

### Project rename: ClawAI -> ClawDefender

The project has been renamed from ClawAI to ClawDefender to better reflect its
purpose as a defensive security tool. All crate names, configuration paths,
binary names, and documentation have been updated.

### AI-powered risk analysis (SLM integration)

ClawDefender now includes an on-device Small Language Model for analyzing tool
calls and assigning risk levels. The SLM evaluates events that hit `prompt`
policy rules and provides advisory risk assessments (LOW / MEDIUM / HIGH /
CRITICAL) with explanations.

Key features:
- **Local inference** -- runs entirely on-device using GGUF model files, no
  data leaves your machine
- **Concurrency control** -- serialized inference with a bounded queue (max 10
  pending requests) to prevent resource exhaustion
- **Metal GPU acceleration** -- optional GPU support on macOS for faster
  inference
- **Advisory only** -- SLM results enrich the audit log and TUI but never
  override policy decisions

### Noise filter

A new noise filtering system suppresses benign developer activity before it
reaches the SLM. Built-in profiles cover compilers, git operations, IDE/LSP
activity, test runners, and package managers. Frequency-based suppression
prevents the same (server, tool) pair from generating excessive SLM calls.
Custom rules can be added via `~/.config/clawdefender/noise.toml`.

### Prompt injection hardening

Multi-layer defense against prompt injection in SLM analysis:
- Input sanitization strips known injection patterns and escapes special
  characters
- Random nonce delimiters prevent attackers from escaping the untrusted data
  wrapper
- Output validation detects echo attacks, injection artifacts, and structural
  anomalies
- Canary token verification confirms SLM responses have not been hijacked

### Model management CLI

New `clawdefender model` subcommands:
- `clawdefender model download` -- download a recommended GGUF model
- `clawdefender model list` -- list installed and available models
- `clawdefender model toggle on|off` -- enable/disable SLM analysis
- `clawdefender model stats` -- view inference statistics

### TUI enhancements

- Risk level badges on prompted events (color-coded by severity)
- SLM status indicator in the header
- Noise-filtered events marked with a visual indicator

### Audit log enhancements

- SLM analysis results (risk level, explanation, confidence, latency) are
  included in audit records when available

## Breaking changes

### Binary and configuration rename

| V1                              | V2                                 |
|---------------------------------|------------------------------------|
| `clawai` binary                 | `clawdefender` binary              |
| `~/.config/clawai/`             | `~/.config/clawdefender/`          |
| `~/.local/share/clawai/`        | `~/.local/share/clawdefender/`     |
| `clawai-core` crate             | `clawdefender-core` crate          |
| `clawai-mcp-proxy` crate        | `clawdefender-mcp-proxy` crate     |

### Migration guide

1. **Rename configuration directory:**
   ```bash
   mv ~/.config/clawai ~/.config/clawdefender
   ```

2. **Rename data directory:**
   ```bash
   mv ~/.local/share/clawai ~/.local/share/clawdefender
   ```

3. **Update MCP client configuration:**
   ```bash
   clawdefender unwrap <server-name>
   clawdefender wrap <server-name>
   ```
   Or manually update `claude_desktop_config.json` to replace `clawai` with
   `clawdefender` in server command paths.

4. **Update shell aliases and scripts:**
   Replace any references to `clawai` with `clawdefender`.

The `clawdefender unwrap` command supports both legacy `_clawai_original` and
new `_clawdefender_original` keys for backward compatibility during migration.

## Crate versions

All crates are at version 0.1.0 in this release. The workspace includes:

| Crate                     | Description                              |
|---------------------------|------------------------------------------|
| `clawdefender-cli`        | Command-line interface                   |
| `clawdefender-core`       | Core types, policy engine, audit         |
| `clawdefender-mcp-proxy`  | MCP proxy (stdio and HTTP)               |
| `clawdefender-sensor`     | OS-level monitoring via eslogger         |
| `clawdefender-slm`        | Small language model integration (new)   |
| `clawdefender-tui`        | Terminal UI                              |
| `clawdefender-daemon`     | Background daemon                        |
| `clawdefender-swarm`      | Multi-agent coordination (planned)       |
