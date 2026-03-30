# ClawDefender SLM Performance Baseline

**Date**: 2026-03-29
**Phase**: 3 (Post-QA, Pre-Integration)
**Status**: Estimated (no live model loaded; based on code analysis and published benchmarks)

---

## 1. System Specifications

| Property             | Value                          |
|----------------------|--------------------------------|
| CPU                  | Apple M1 Pro (10-core)         |
| Architecture         | arm64 (Apple Silicon)          |
| RAM                  | 32 GB                          |
| GPU                  | Apple M1 Pro, 16-core GPU      |
| Metal Support        | Metal 4                        |
| Storage              | SSD (Apple Fabric protocol)    |
| macOS                | 26.4 (Build 25E246)            |

---

## 2. Model Catalog Performance Estimates

All models use Q4_K_M quantization. Estimates are from the curated catalog in
`crates/clawdefender-slm/src/model_registry.rs`.

| Model               | File Size | Min RAM | tok/s (Apple Silicon) | tok/s (Intel) | Quality | Default |
|----------------------|-----------|---------|----------------------:|-------------:|---------|---------|
| Gemma 3 1B          | 806 MB    | 2 GB    |                    80 |           35 | 3/5     | No      |
| Qwen3 1.7B          | 1.1 GB    | 4 GB    |                    55 |           20 | 4/5     | Yes     |
| Phi-4 Mini 3.8B     | 2.5 GB    | 8 GB    |                    32 |           11 | 4/5     | No      |
| Qwen3 4B            | 2.5 GB    | 8 GB    |                    35 |           12 | 5/5     | No      |
| Gemma 3 4B          | 2.5 GB    | 8 GB    |                    33 |           12 | 5/5     | No      |

### Model Recommendation Logic

From `model_registry.rs:recommend_model()`:

| RAM Available | Recommended Model | Rationale                         |
|--------------|-------------------|-----------------------------------|
| < 8 GB       | Gemma 3 1B        | Smallest footprint, fastest       |
| 8-15 GB      | Qwen3 1.7B        | Best speed/quality balance        |
| 16+ GB       | Qwen3 4B          | Highest quality, thinking mode    |

**This system (32 GB)** would be recommended Qwen3 4B, but the default is Qwen3 1.7B.

---

## 3. Inference Configuration Defaults

From `crates/clawdefender-slm/src/engine.rs`:

| Parameter          | Default Value       | Source                                 |
|--------------------|--------------------:|----------------------------------------|
| context_size       | 1,024 tokens        | `default_context_size()`               |
| max_output_tokens  | 256 tokens          | `default_max_output_tokens()`          |
| temperature        | 0.1                 | `default_temperature()` (deterministic)|
| threads            | `num_cpus / 2`      | `default_threads()` (= 5 on this system)|
| use_gpu            | true                | `default_use_gpu()` (Metal on macOS)   |
| batch_size         | 512                 | `default_batch_size()`                 |
| chat_template      | ChatML              | `default_chat_template()`              |

### Concurrency Control

| Parameter           | Value  | Description                                          |
|---------------------|-------:|------------------------------------------------------|
| Inference semaphore | 1      | Only 1 inference runs at a time (serialized)         |
| Queue depth         | 10     | Max 10 requests waiting; excess fail-closed to HIGH  |
| Inference timeout   | 30 sec | Hard wall-clock cutoff per inference                 |
| Slow threshold      | 2 sec  | Log warning if inference exceeds this                |

---

## 4. Token Budget Analysis

### 4.1 System Prompt Size

The system prompt is hardcoded in `crates/clawdefender-slm/src/analyzer.rs:68-95`.

**Raw character count**: ~880 characters
**Estimated token count**: ~220 tokens (at ~4 chars/token for English text)

The system prompt includes:
- MCP context explanation
- 12 risk classification rules
- Output format specification (RISK/EXPLANATION/CONFIDENCE)

### 4.2 Chat Template Overhead

Each template adds wrapper tokens. Measured for ChatML (default for Qwen3):

```
<|im_start|>system\n{system_prompt}<|im_end|>\n
<|im_start|>user\n{user_prompt}<|im_end|>\n
<|im_start|>assistant\n
```

**Template overhead**: ~30 tokens (special tokens + newlines)

### 4.3 User Prompt Sizes

#### Simple MCP Tool Call (no context)

A minimal `build_user_prompt()` for a tool call with no recent events:

```
Analyze the following action for security risk.

Server: <UNTRUSTED_DATA>test-server</UNTRUSTED_DATA>
Client: <UNTRUSTED_DATA>cursor</UNTRUSTED_DATA>
Event: MCP Tool Call
Tool: <UNTRUSTED_DATA>read_file</UNTRUSTED_DATA>
Arguments (truncated): <UNTRUSTED_DATA>&#123;"path": "/tmp/test"&#125;</UNTRUSTED_DATA>

Server history: 10 allowed, 2 blocked, 1 prompted
```

**Estimated**: ~120 tokens

#### Correlated Event with OS Activity and History

With 3 recent events and longer arguments:

```
[Above base prompt]
Recent activity:
- [<UNTRUSTED_DATA>2025-01-01T00:00:00Z</UNTRUSTED_DATA>] <UNTRUSTED_DATA>read_file /home/user/.ssh/id_rsa</UNTRUSTED_DATA>
- [<UNTRUSTED_DATA>2025-01-01T00:01:00Z</UNTRUSTED_DATA>] <UNTRUSTED_DATA>shell_exec curl https://example.com</UNTRUSTED_DATA>
- [<UNTRUSTED_DATA>2025-01-01T00:02:00Z</UNTRUSTED_DATA>] <UNTRUSTED_DATA>write_file /tmp/exfil.txt</UNTRUSTED_DATA>
```

**Estimated**: ~250 tokens

### 4.4 Total Context Utilization

| Scenario                        | System | Template | User  | Total Input | Output | Grand Total | Headroom |
|--------------------------------|-------:|---------:|------:|------------:|-------:|------------:|---------:|
| Simple tool call (no context)   |    220 |       30 |   120 |         370 |    256 |         626 |  **398** |
| Tool call + 3 recent events     |    220 |       30 |   250 |         500 |    256 |         756 |  **268** |
| Max args (500 chars) + 5 events |    220 |       30 |   400 |         650 |    256 |         906 |  **118** |
| Worst case (all fields maxed)   |    220 |       30 |   500 |         750 |    256 |       1,006 |   **18** |

**Assessment**: The default context_size of 1,024 tokens is **tight but workable** for typical
events. Worst-case scenarios with maximum argument sizes and many recent events leave only
~18 tokens of headroom, which could cause context overflow and garbled output.

**Recommendation**: Increase `context_size` to 2,048 for safety margin, especially for 4B
models which have sufficient RAM. The 1B model should stay at 1,024 to avoid OOM on
low-RAM systems.

### 4.5 Output Token Budget

The expected output format is exactly 3 lines:

```
RISK: CRITICAL
EXPLANATION: SSH key access followed by outbound network connection suggests data exfiltration.
CONFIDENCE: 0.92
```

**Typical output**: 20-40 tokens
**max_output_tokens setting**: 256

The 256-token budget is **more than adequate**. The model should never need more than
~60 tokens for the structured output, even with a verbose explanation. The large budget
acts as a safety margin for models that produce preamble text (which the parser ignores).

---

## 5. Throughput Analysis

### 5.1 Per-Inference Latency

With the default Qwen3 1.7B at 55 tok/s on Apple Silicon:

| Phase               | Tokens | Time (ms) | Notes                            |
|---------------------|-------:|----------:|----------------------------------|
| Prompt evaluation   |   ~400 |      ~100 | batch_size=512, near-instant     |
| Token generation    |    ~35 |      ~636 | 35 output tokens at 55 tok/s     |
| Overhead (parsing)  |      - |        ~5 | String operations, regex parsing |
| **Total per event** |      - |   **~741**| Well under 2s slow threshold     |

**Estimated**: ~0.74 seconds per inference for a typical event

### 5.2 Events Per Minute (Raw Throughput)

| Model           | tok/s (Apple Si) | Est. Latency (ms) | Events/min (max) |
|-----------------|------------------:|-------------------:|-----------------:|
| Gemma 3 1B      |                80 |                538 |               ~111|
| Qwen3 1.7B      |                55 |                736 |               ~81 |
| Phi-4 Mini 3.8B |                32 |               1194 |               ~50 |
| Qwen3 4B        |                35 |               1100 |               ~54 |
| Gemma 3 4B      |                33 |               1161 |               ~51 |

**Note**: This is raw throughput with Semaphore(1) serialized inference. Only 1 inference
runs at a time.

### 5.3 Queue Behavior Under Load

With `MAX_QUEUED = 10` and Qwen3 1.7B:

- **Queue capacity**: 1 running + 10 waiting = 11 concurrent requests
- **Queue drain time**: 11 * 0.74s = ~8.1 seconds to drain a full queue
- **Overflow behavior**: Request 12+ returns `RiskLevel::High` immediately (fail-closed)
- **Overflow latency**: 0 ms (immediate return, no inference)

**Sustained load tolerance**: If events arrive faster than ~81/min (~1.35/sec) for the
default model, the queue will gradually fill and start dropping requests to HIGH risk.

### 5.4 Noise Filter Impact

The noise filter in `crates/clawdefender-slm/src/noise_filter.rs` has 5 built-in profiles
with extensive rules. From `crates/clawdefender-slm/src/profiles.rs`:

| Profile          | Filters                                                      |
|------------------|--------------------------------------------------------------|
| Compiler         | gcc, clang, rustc, cargo build/test/check, make, ninja, target/build/node_modules dirs |
| Package Manager  | npm, yarn, pip, brew, cargo install, lock files              |
| IDE              | language servers, LSP, copilot, rust-analyzer, etc.          |
| Git              | git status/log/diff/add/commit/push/pull, .git/ access      |
| Test Runner      | pytest, jest, mocha, cargo test, go test, npm test           |

**Plus frequency suppression**: Same (server, tool) pair is suppressed after 5 occurrences
in a 10-minute window.

#### Estimated Filter Rates for Typical Developer Workloads

During active AI-assisted development (e.g., Cursor, Claude Code, Copilot):

| Activity Category           | Events/min (est.) | Filtered? | Reaches SLM? |
|-----------------------------|-------------------:|-----------|:-------------|
| LSP/language server calls   |              20-50 | Yes       | 0            |
| Compiler/build invocations  |               5-15 | Yes       | 0            |
| Git operations              |               2-10 | Yes       | 0            |
| File reads in project dirs  |              10-30 | Partially | ~5-15        |
| File reads in build dirs    |               5-10 | Yes       | 0            |
| Shell commands              |               1-5  | No        | 1-5          |
| Network/external access     |               0-2  | No        | 0-2          |
| Package manager operations  |               0-3  | Yes       | 0            |
| **Total**                   |          **43-125**|           | **~6-22**    |

**Estimated filter rate**: 75-90% of events are filtered before reaching the SLM.

**Effective throughput needed**: With ~6-22 events/min reaching the SLM and ~81 events/min
capacity (Qwen3 1.7B), the system has **3-13x headroom** for typical workloads.

This means the queue should almost never fill up during normal development.

---

## 6. Cold Start Analysis

### 6.1 Model Loading

From `crates/clawdefender-slm/src/gguf_backend.rs:34-95`:

| Phase                    | Qwen3 1.7B (1.1 GB) | Qwen3 4B (2.5 GB) | Notes                            |
|--------------------------|---------------------:|-------------------:|----------------------------------|
| Security checks          |              ~1 ms   |            ~1 ms   | symlink check, metadata read     |
| File mmap                |           ~50-100 ms |        ~100-200 ms | SSD sequential read              |
| llama.cpp model parsing  |          ~200-500 ms |        ~400-800 ms | Weight deserialization, tensor setup |
| Metal GPU initialization |          ~100-300 ms |        ~200-500 ms | Shader compilation, buffer alloc |
| **Total cold start**     |      **~350-900 ms** |   **~700-1500 ms** |                                  |

### 6.2 Factors Affecting Cold Start

- **First run after boot**: Slower due to Metal shader compilation cache being cold
- **Subsequent runs**: Faster due to OS file cache and Metal shader cache
- **SSD speed**: Apple Fabric SSD delivers ~5-7 GB/s sequential read; model file I/O is not the bottleneck
- **Memory pressure**: If RAM is under pressure, mmap pages may need to be loaded on-demand during first inference

### 6.3 Warm State

After the first inference:
- Model weights remain memory-mapped (effectively zero-cost access)
- Metal GPU context persists across inferences
- No per-request overhead beyond context creation (~1-5 ms)

---

## 7. Configuration Recommendations

### Tier 1: Low RAM (< 8 GB)

| Setting          | Value          | Rationale                                       |
|------------------|---------------:|------------------------------------------------|
| Model            | Gemma 3 1B     | Only model that fits in 2 GB                    |
| context_size     | 1,024          | Keep small to save memory                       |
| max_output_tokens| 128            | Output rarely exceeds 60 tokens                 |
| threads          | 2              | Minimize CPU contention                         |
| use_gpu          | true           | Essential for acceptable speed                  |
| batch_size       | 256            | Smaller batches reduce peak memory              |

**Expected**: ~80 tok/s, ~0.5s/event, ~111 events/min max

### Tier 2: Medium RAM (8-16 GB) -- Default

| Setting          | Value          | Rationale                                       |
|------------------|---------------:|------------------------------------------------|
| Model            | Qwen3 1.7B     | Best speed/quality balance                      |
| context_size     | 1,024          | Adequate for most events                        |
| max_output_tokens| 256            | Comfortable headroom                            |
| threads          | `ncpu/2`       | Default is good                                 |
| use_gpu          | true           | Significant speedup on Apple Silicon            |
| batch_size       | 512            | Good balance                                    |

**Expected**: ~55 tok/s, ~0.74s/event, ~81 events/min max

### Tier 3: High RAM (16+ GB)

| Setting          | Value          | Rationale                                       |
|------------------|---------------:|------------------------------------------------|
| Model            | Qwen3 4B       | Highest quality reasoning                       |
| context_size     | 2,048          | More headroom for complex events with context   |
| max_output_tokens| 256            | Same output, better reasoning with more context |
| threads          | `ncpu/2`       | Default is good                                 |
| use_gpu          | true           | Essential for 4B model speed                    |
| batch_size       | 512            | Good balance                                    |

**Expected**: ~35 tok/s, ~1.1s/event, ~54 events/min max

---

## 8. Optimization Opportunities (Phase 6+)

### High Priority

1. **Increase context_size to 2,048 for Tier 2-3**:
   Current 1,024 is tight for events with full context history.
   Cost: ~2x KV cache memory (~50 MB more for 1.7B model).

2. **Speculative decoding / prompt caching**:
   The system prompt is identical for every request. llama.cpp supports
   prompt caching (reuse KV cache for the common prefix). This would
   skip ~220 tokens of re-evaluation per inference, saving ~4-8 ms.

3. **Batch inference for queued requests**:
   Currently Semaphore(1) serializes all inference. With llama.cpp's
   continuous batching, multiple requests could share a single forward
   pass for the common system prompt prefix.

### Medium Priority

4. **Adaptive noise filter thresholds**:
   The frequency threshold (5 events per 10 minutes) is static.
   Under sustained load, the threshold could auto-decrease to
   reduce SLM load.

5. **Response caching**:
   Many tool calls are structurally identical (e.g., `read_file` with
   different paths in the same project directory). A short-lived LRU
   cache keyed on (tool, path_prefix) could skip duplicate analysis.

6. **Context size auto-tuning**:
   Measure actual token usage at runtime and alert if prompts consistently
   exceed 80% of context_size. Auto-reduce recent_events count when
   context pressure is high.

### Low Priority

7. **Multi-model routing**:
   Use the fast 1B model for simple events (single tool calls with
   no context) and the 4B model for complex events (correlated
   activity, suspicious patterns).

8. **Quantization upgrade path**:
   Q4_K_M is the sweet spot for speed/quality. Q5_K_M or Q6_K
   could improve quality by ~5-10% at the cost of ~20-30% more
   memory and ~15-20% slower inference. Worth offering as a
   "high security" mode.

---

## 9. Summary

| Metric                          | Value                               |
|---------------------------------|-------------------------------------|
| Default model                   | Qwen3 1.7B Q4_K_M                  |
| Inference latency (typical)     | ~740 ms                             |
| Raw throughput                  | ~81 events/min                      |
| Noise filter rate               | 75-90% of events filtered           |
| Effective events reaching SLM   | ~6-22/min (typical dev workload)    |
| Throughput headroom             | 3-13x over typical demand           |
| Context utilization             | 60-90% (tight at worst case)        |
| Cold start time                 | 0.35-1.5 sec depending on model     |
| Queue overflow behavior         | Fail-closed to HIGH risk            |
| Inference timeout               | 30 seconds (hard limit)             |

**Conclusion**: The SLM pipeline is well-architected for real-time security monitoring.
The noise filter dramatically reduces SLM load, and the default Qwen3 1.7B model
provides sufficient throughput for typical AI-assisted development workflows with
comfortable headroom. The primary optimization needed before Phase 6 integration is
increasing context_size to 2,048 for medium/high RAM systems to prevent context
overflow on complex events.
