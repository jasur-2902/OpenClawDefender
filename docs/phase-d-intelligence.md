# Phase D: Intelligence Integration

Phase D connects the AI subsystems (SLM, behavioral engine, swarm) to the live
event pipeline and exposes them through the daemon, CLI, and desktop app.

## What Was Connected

1. **GGUF backend compilation** -- The `gguf` feature flag is enabled in the
   daemon, CLI, and Tauri app Cargo.toml files, linking llama.cpp via
   `llama-cpp-2` for local inference on GGUF model files.

2. **Behavioral engine wired to sensor events** -- The `EventRouter` feeds
   correlated MCP and OS events into the learning engine, anomaly scorer,
   kill-chain detector, and decision engine. Results are written to audit
   records but never alter policy decisions.

3. **SLM and swarm escalation** -- Uncorrelated high-severity events are
   analyzed asynchronously by the SLM. If the SLM rates an event as Critical,
   or the event itself is Critical, the swarm commander is invoked. Both
   results enrich audit logs only.

4. **Model hot-swap** -- The Tauri `activate_model` command unloads the
   current model (take + drop pattern with GPU memory release pause), loads
   the new GGUF file, and installs it without restarting the daemon.

5. **Sensor config hot-reload** -- A file watcher on the sensor config path
   debounces changes and writes the new `SensorConfig` into the shared
   `Arc<RwLock<SensorConfig>>`, updating filter settings live.

6. **Frontend AI status** -- The dashboard shows an AI status indicator
   reflecting whether a model is loaded, its name, and inference statistics.
   The IPC status response includes `slm_status` and `behavioral_status`.

## Build Prerequisites

### macOS (primary target)

- **Xcode Command Line Tools**: Required for llama.cpp compilation.
  Install with `xcode-select --install`.
- **Rust toolchain**: stable, via rustup.
- **Node.js 18+** and **pnpm**: for the Tauri frontend.

The `gguf` feature compiles llama.cpp from source via the `llama-cpp-2` crate.
No pre-built binaries are required. Metal (GPU) acceleration is used
automatically on Apple Silicon.

### Building

```bash
cargo build --workspace          # all crates
cd clients/clawdefender-app && pnpm tauri build   # desktop app
```

## Advisory-Only Safety Property

All AI subsystem outputs are **advisory only**. This is enforced architecturally:

- The **policy engine** (`clawdefender-core/src/policy/engine.rs`) has zero
  references to SLM, swarm, or behavioral types. Policy decisions are made
  solely from static rules.
- **SLM and swarm results** flow exclusively to `audit_tx` (the audit logger
  channel). SAFETY comments mark every code path where results are produced.
- **Behavioral auto-block** is gated by `config.behavioral.auto_block_enabled`,
  which defaults to `false`. When disabled, high anomaly scores produce
  enriched prompts (informational) rather than blocks.
- **SLM prompts** wrap all untrusted data in `<UNTRUSTED_DATA>` tags with
  length truncation to prevent prompt injection.
- **SLM output validation** checks for echo attacks (nonce detection),
  injection artifacts, and clamps confidence to [0.0, 1.0]. Invalid output
  falls back to a HIGH risk advisory with zero confidence.

## Setting Up a Local AI Model

1. **Download a model** from the app's AI Settings panel, or place a GGUF file
   in `~/.local/share/clawdefender/models/`.
2. **Activate the model** via the UI "Activate" button or the CLI:
   ```bash
   clawdefender slm activate <model-id-or-path>
   ```
3. **Verify** by checking the dashboard AI status indicator or:
   ```bash
   clawdefender slm status
   ```

The `activate_model` command safely unloads any existing model before loading
the new one, avoiding GPU memory leaks.

## Behavioral Engine

### Learning Phase

The learning engine observes MCP tool calls, resource reads, and OS-level
file/network/process events per server. It builds a behavioral profile
including tool usage frequency, file access patterns, network destinations,
and temporal patterns. The profile is used as the baseline for anomaly scoring.

### Detection Capabilities

- **Anomaly scoring**: Compares current events against the learned profile.
  Scores > 0.7 are flagged; scores > 0.9 (configurable threshold) can trigger
  auto-block if the user has enabled it.
- **Kill-chain detection**: Tracks multi-step attack patterns (reconnaissance,
  lateral movement, exfiltration) across events. Kill-chain matches boost the
  anomaly score.
- **Decision engine**: Combines anomaly score and kill-chain results. Outputs
  one of: PassThrough, EnrichedPrompt (informational warning), or AutoBlock
  (only when explicitly enabled by user).

## Swarm Escalation

### When It Triggers

Swarm analysis is triggered when:
- The SLM rates an event as **Critical** risk, OR
- The event itself has **Critical** severity

### Advisory-Only Constraint

The swarm verdict (risk level, explanation, recommended action, specialist
reports) is written to the audit log. It never modifies, overrides, or
influences policy engine decisions. The swarm commander has a built-in
10-second timeout per analysis.

## Known Limitations

- **GGUF-only local inference**: Only GGUF model format is supported for local
  models. Other formats (ONNX, SafeTensors) are not supported.
- **macOS-only sensor**: The eslogger-based sensor requires macOS with Full
  Disk Access. The behavioral engine works on all platforms but OS event
  correlation is macOS-specific.
- **Learning phase cold start**: The behavioral engine needs to observe normal
  activity before anomaly detection is meaningful. New server profiles start
  with no baseline.
- **SLM quality depends on model**: Smaller GGUF models (e.g., 1-3B parameters)
  may produce lower quality risk assessments. The output validator provides a
  safety net but cannot improve model reasoning.
- **Swarm requires cloud API keys**: Swarm escalation uses cloud LLM providers
  and requires configured API keys. Without keys, swarm analysis is skipped
  silently.
- **Auto-block disabled by default**: The behavioral auto-block feature is
  opt-in. Users must explicitly enable it in configuration after gaining
  confidence in the behavioral engine's accuracy for their workload.
