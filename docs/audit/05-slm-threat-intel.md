# Audit Report: SLM Engine & Threat Intelligence

> Auditor: Agent 5 (SLM & Threat Intel Auditor)
> Date: 2026-02-23
> Scope: `crates/clawdefender-slm/`, `crates/clawdefender-threat-intel/`, `threat-feed/`

Classification key:
- **REAL** -- Production-quality implementation with actual logic
- **PARTIAL** -- Functional but incomplete or has known gaps
- **STUBBED** -- Skeleton/placeholder, returns hardcoded or no-op values
- **MISSING** -- Referenced or expected but not implemented

---

## Section 5: SLM Engine (`crates/clawdefender-slm`)

### 5.1 Overview

The SLM crate provides small-language-model inference for security policy decisions. It uses a trait-based backend abstraction (`SlmBackend`) with three implementations: a real GGUF/llama.cpp backend, a real cloud API backend, and a mock backend for testing. Feature flags (`gguf`, `cloud`, `download`) gate the heavy dependencies.

**Files audited (14 source files + Cargo.toml):**
- `src/lib.rs`, `src/engine.rs`, `src/gguf_backend.rs`, `src/cloud_backend.rs`
- `src/model_registry.rs`, `src/model_manager.rs`, `src/downloader.rs`
- `src/analyzer.rs`, `src/context.rs`, `src/sanitizer.rs`
- `src/noise_filter.rs`, `src/output_validator.rs`, `src/profiles.rs`

### 5.2 GGUF Backend Reality

| Item | Classification | Notes |
|------|---------------|-------|
| `GgufBackend::load()` | **REAL** | Calls `llama_cpp::LlamaModel::load_from_file()` with `LlamaParams` (GPU layers, context size) |
| `GgufBackend::infer()` | **REAL** | Creates session, advances context with ChatML tokens (`<\|im_start\|>`), calls `start_completing()`, collects tokens with stop-sequence detection |
| GPU detection | **REAL** | Reads `gpu_layers` from params, reports via `using_gpu()` |
| Symlink rejection | **REAL** | Refuses to load model files that are symlinks (security measure) |
| Thread safety | **REAL** | Inference runs in `spawn_blocking` to avoid blocking the async runtime |

**Verdict: REAL.** The GGUF backend is a fully functional llama.cpp integration. It is gated behind the `gguf` feature flag and the `llama_cpp = "0.3"` optional dependency.

### 5.3 Cloud Backend Reality

| Item | Classification | Notes |
|------|---------------|-------|
| `CloudBackend::infer()` | **REAL** | Makes actual HTTP POST requests to provider APIs |
| Anthropic integration | **REAL** | `api.anthropic.com/v1/messages` with `anthropic-version` header, `x-api-key` auth |
| OpenAI integration | **REAL** | `api.openai.com/v1/chat/completions` with Bearer token auth |
| Google Gemini integration | **REAL** | `generativelanguage.googleapis.com/v1beta` with `x-goog-api-key` header (not query param -- good security) |
| API key storage | **REAL** | macOS Keychain via `security find-generic-password` / `add-generic-password` CLI |
| Token tracking | **REAL** | Tracks input/output token counts and estimates cost per provider |
| Error handling | **REAL** | HTTP status checks, JSON parsing, provider-specific error extraction |

**Verdict: REAL.** The cloud backend makes genuine API calls to three major LLM providers with proper authentication and error handling.

### 5.4 Mock Separation

| Item | Classification | Notes |
|------|---------------|-------|
| `MockSlmBackend` | **REAL** (test utility) | Lives in `engine.rs`, implements `SlmBackend`, returns configurable canned responses |
| Separation from production code | **REAL** | Mock is only used when no real backend is available (no `gguf` feature, no model file) or in tests |
| `SlmService` fallback logic | **REAL** | `lib.rs` tries GGUF first (if feature enabled + model exists), then falls back to mock with log warning |

**Verdict: REAL.** Mock is cleanly separated. Production path prefers real backends.

### 5.5 Feature Flags

| Flag | Dependencies | Purpose | Classification |
|------|-------------|---------|---------------|
| `gguf` | `llama_cpp` | Local GGUF inference | **REAL** |
| `cloud` | `reqwest` | Cloud API backends | **REAL** |
| `download` | `reqwest`, `sha2`, `futures-util`, `tokio-util`, `uuid`, `libc` | Model downloading | **REAL** |
| `default` | (none) | Ships with no heavy deps by default | **REAL** |

All feature flags are properly wired with `#[cfg(feature = "...")]` guards throughout the codebase.

### 5.6 Model Registry URLs

| Model | URL Target | Classification |
|-------|-----------|---------------|
| Qwen3-1.7B Q4_K_M | `huggingface.co/unsloth/Qwen3-1.7B-GGUF` | **REAL** (valid HF repo) |
| Qwen3-4B Q4_K_M | `huggingface.co/Qwen/Qwen3-4B-GGUF` | **REAL** (valid HF repo) |
| Phi-4-mini Q4_K_M | `huggingface.co/microsoft/Phi-4-mini-instruct-GGUF` | **REAL** (valid HF repo) |
| Gemma-3-1B Q4_K_M | `huggingface.co/google/gemma-3-1b-it-GGUF` | **REAL** (valid HF repo) |
| Gemma-3-4B Q4_K_M | `huggingface.co/google/gemma-3-4b-it-GGUF` | **REAL** (valid HF repo) |

**Note:** SHA-256 checksums are all zeros (placeholder). This means checksum verification is effectively **skipped** at download time. The downloader code checks `sha256 != "0".repeat(64)` before verifying.

**Cloud providers registered:** Anthropic (claude-sonnet-4, claude-haiku-4), OpenAI (gpt-4o-mini, gpt-4o), Google (gemini-2.0-flash, gemini-2.5-pro). All are current production model IDs.

**Verdict: REAL URLs, PARTIAL checksums** (placeholders -- need real SHA-256 values before production release).

### 5.7 Downloader

| Item | Classification | Notes |
|------|---------------|-------|
| `DownloadManager` | **REAL** | Full download lifecycle management |
| HTTP streaming | **REAL** | Uses reqwest `bytes_stream()` with chunked progress tracking |
| Resume support | **REAL** | HTTP `Range` header for partial downloads, `.part` temp files |
| SHA-256 verification | **REAL** | Streaming hash computation, verified after download completes |
| Cancellation | **REAL** | `CancellationToken` for cooperative cancellation |
| Disk space check | **REAL** | Uses `libc::statvfs` to verify free space before download |
| URL validation | **REAL** | Enforces HTTPS-only URLs |
| Path traversal prevention | **REAL** | Strips directory components from filenames |
| `ModelManager::download()` | **REAL** | Simpler download path in model_manager.rs, also streams + SHA-256 verifies |

**Verdict: REAL.** Full-featured, production-ready download system with proper security measures.

### 5.8 Analyzer Prompts

| Item | Classification | Notes |
|------|---------------|-------|
| `SYSTEM_PROMPT` | **REAL** | Hardcoded security-analysis system prompt instructing risk assessment |
| `build_user_prompt()` | **REAL** | Wraps untrusted data in `<UNTRUSTED_DATA>` tags, strips XML, truncates to 500 chars |
| `parse_slm_output()` | **REAL** | Extracts `RISK:`, `CONFIDENCE:`, `EXPLANATION:` fields with sanitization |
| Output sanitization | **REAL** | Strips URLs, code blocks, XML tags from explanations; enforces 200-char limit |

**Verdict: REAL.** Prompt construction and output parsing are fully implemented with security hardening.

### 5.9 Model Hot-Swapping

| Item | Classification | Notes |
|------|---------------|-------|
| Runtime model switching | **PARTIAL** | No dedicated hot-swap API. `ActiveModelConfig` is persisted to TOML and read at startup. Switching requires reconstructing `SlmService`. |
| `ActiveModelConfig` persistence | **REAL** | Saved to `~/.local/share/clawdefender/model_config.toml` |

**Verdict: PARTIAL.** Config persistence exists but there is no live hot-swap mechanism -- changing models requires service restart or reconstruction.

### 5.10 SlmService Integration

| Item | Classification | Notes |
|------|---------------|-------|
| `SlmService::new()` | **REAL** | Constructs engine with appropriate backend based on feature flags and model availability |
| `analyze_event()` | **REAL** | Builds prompt from event data, runs inference, parses output, returns `SlmVerdict` |
| `analyze_scan_finding()` | **REAL** | Analyzes scanner findings with dedicated prompt |
| `assess_server_config()` | **REAL** | Reviews server configuration for security issues |
| Env-var safety | **REAL** | Only sends environment variable *names* to SLM, never values |

**Verdict: REAL.** The service layer is complete and functional.

### 5.11 Security Subsystems

| Item | Classification | Notes |
|------|---------------|-------|
| `sanitizer.rs` - Prompt injection prevention | **REAL** | Multi-layer: truncation, XML/HTML stripping, 9 injection pattern filters, special char escaping, random nonce delimiters, canary tokens |
| `output_validator.rs` - Output validation | **REAL** | Echo attack detection (nonce in output), injection artifact detection (4 patterns), structural parsing, falls back to HIGH risk on failure |
| `noise_filter.rs` - Noise reduction | **REAL** | 5 built-in profiles (compiler, package_manager, ide, git, test_runner), frequency suppression (5 events in 10min), custom rules from `~/.config/clawdefender/noise.toml` |
| `context.rs` - Context tracking | **REAL** | Per-server ring buffer (max 20 events), reputation counters (allowed/blocked/prompted) |
| `profiles.rs` - Activity profiles | **REAL** | Built-in profiles with regex tool/argument patterns and server glob patterns, custom TOML rules |

**Verdict: REAL.** All security subsystems are fully implemented.

### 5.12 SLM Engine Summary

| Subsystem | Classification |
|-----------|---------------|
| GGUF backend (llama.cpp) | **REAL** |
| Cloud backend (Anthropic/OpenAI/Google) | **REAL** |
| Mock backend separation | **REAL** |
| Feature flag architecture | **REAL** |
| Model registry URLs | **REAL** (checksums are placeholders) |
| Downloader | **REAL** |
| Analyzer prompts & parsing | **REAL** |
| Model hot-swapping | **PARTIAL** (config persists, no live swap) |
| SlmService integration | **REAL** |
| Prompt injection prevention | **REAL** |
| Output validation | **REAL** |
| Noise filtering | **REAL** |
| Context tracking | **REAL** |

**Overall SLM verdict: REAL with minor gaps.** The crate is production-quality. Two items need attention before release: (1) SHA-256 checksums for model files are placeholders, and (2) model hot-swapping requires service reconstruction rather than live swap.

---

## Section 10: Threat Intelligence (`crates/clawdefender-threat-intel`)

### 10.1 Overview

The threat intelligence crate implements a feed-based threat data system with Ed25519-signed updates, blocklist matching, indicator-of-compromise (IoC) detection, community rule packs, pattern loading (kill chain + injection), behavioral profile seeding, and anonymous telemetry. It includes a bundled baseline feed for offline/first-run scenarios.

**Files audited (28+ source files + Cargo.toml + feed data):**
- `src/lib.rs`, `src/client.rs`, `src/types.rs`, `src/error.rs`, `src/cache.rs`, `src/signature.rs`, `src/baseline.rs`
- `src/blocklist/mod.rs`, `types.rs`, `matching.rs`, `tests.rs`
- `src/ioc/mod.rs`, `types.rs`, `engine.rs`, `database.rs`, `tests.rs`
- `src/patterns/mod.rs`, `types.rs`, `killchain_loader.rs`, `injection_loader.rs`, `profile_seeder.rs`, `tests.rs`
- `src/rules/mod.rs`, `types.rs`, `catalog.rs`, `manager.rs`, `conflict.rs`
- `src/telemetry/mod.rs`, `types.rs`, `consent.rs`, `aggregator.rs`, `reporter.rs`
- `threat-feed/feed/v1/manifest.json`, `threat-feed/feed/v1/blocklist.json`

### 10.2 Feed Client & Downloads

| Item | Classification | Notes |
|------|---------------|-------|
| `FeedClient::check_update()` | **REAL** | Fetches manifest via HTTP, verifies Ed25519 signature, downloads only changed files (hash comparison) |
| Incremental updates | **REAL** | Compares SHA-256 hashes of local vs remote files; only downloads changed ones |
| Signature verification | **REAL** | Ed25519 via `ed25519-dalek` crate, verifies manifest signature before processing |
| Key rotation | **REAL** | Supports `next_public_key` in manifest for graceful key transitions; both current and next key accepted |
| Offline fallback | **REAL** | Uses cached data when network unavailable |
| Bundled baseline | **REAL** | `include_str!` embeds baseline manifest + blocklist for first-run without network |
| HTTP mocking in tests | **REAL** | Integration tests use `mockito` for deterministic testing |

**Note:** `EMBEDDED_PUBLIC_KEY_HEX` in `signature.rs` is all zeros (placeholder). This means signature verification effectively passes anything in development but needs a real Ed25519 public key for production.

**Verdict: REAL.** Feed client is fully functional with proper incremental updates and signature verification. Placeholder key needs replacement for production.

### 10.3 Blocklist

| Item | Classification | Notes |
|------|---------------|-------|
| `BlocklistMatcher` | **REAL** | Thread-safe (`Arc<RwLock<>>`) matcher with atomic runtime updates |
| Name matching | **REAL** | Case-insensitive server name comparison |
| Version matching | **REAL** | Exact version match + semver range support (`<`, `<=`, `>`, `>=`, `=`, comma conjunction) |
| SHA-256 matching | **REAL** | Matches against known malicious file hashes |
| npm package matching | **REAL** | Matches npm package names |
| Entry types | **REAL** | `MaliciousServer`, `VulnerableServer`, `CompromisedVersion` with appropriate metadata |
| Override mechanism | **REAL** | Users can override blocklist entries with required confirmation text ("I understand the risk") |
| Severity levels | **REAL** | Critical, High, Medium, Low with appropriate threat indicators |
| CVE tracking | **REAL** | Entries can reference CVE IDs |

**Verdict: REAL.** Complete blocklist system with rich matching capabilities.

### 10.4 IoC Database & Engine

| Item | Classification | Notes |
|------|---------------|-------|
| `IoCEngine` | **REAL** | High-performance matching engine |
| IP matching | **REAL** | `HashSet` for exact IPs + CIDR range parsing |
| Domain matching | **REAL** | Aho-Corasick automaton for multi-pattern domain matching |
| URL matching | **REAL** | Contained in domain/hash matching |
| File hash matching | **REAL** | `HashSet<String>` for O(1) lookups |
| File path matching | **REAL** | `glob::Pattern` for path glob matching |
| Process name matching | **REAL** | `HashSet<String>` for exact process name lookups |
| Command line matching | **REAL** | Compiled `Regex` patterns |
| Tool sequence matching | **REAL** | Subsequence matching algorithm |
| Argument pattern matching | **REAL** | Compiled `Regex` patterns |
| `IoCDatabase` | **REAL** | Manages indicators with file/directory loading, deduplication, expiration (90 days default, permanent flag), engine rebuild |
| Thread safety | **REAL** | `Arc<IoCEngine>` for lock-free read access during matching |
| Performance | **REAL** | Test: 10K events through 1K indicators in <1 second |

**Indicator types (9):** MaliciousIP, MaliciousDomain, MaliciousURL, MaliciousFileHash, SuspiciousFilePath, SuspiciousProcessName, SuspiciousCommandLine, SuspiciousToolSequence, SuspiciousArgPattern.

**Verdict: REAL.** Production-grade IoC engine with high-performance data structures.

### 10.5 Rule Packs (Community Rules)

| Item | Classification | Notes |
|------|---------------|-------|
| `CommunityRule` | **REAL** | Action (Allow/Deny/Prompt), method/path matching, descriptive messages |
| `RuleCatalog` | **REAL** | Reads available packs from feed cache, persists installed packs, server recommendations |
| `RulePackManager` | **REAL** | Install/uninstall/update lifecycle, `update_all()` checks for newer versions |
| `ConflictDetector` | **REAL** | Detects conflicts between community and user rules (Overridden, Contradicts), path glob overlap heuristic |
| `RuleSource` precedence | **REAL** | User > ThreatIntel > Community > Default |

**Verdict: REAL.** Complete community rule pack system with lifecycle management and conflict detection.

### 10.6 Pattern Loading

| Item | Classification | Notes |
|------|---------------|-------|
| Kill chain loader | **REAL** | Parses feed JSON into kill chain patterns, stage string parsing (`file_read:~/.ssh/*`), merges with built-ins (dedup by ID), hot-reload payload generation |
| Injection signature loader | **REAL** | Loads from feed, validates regex before inclusion, 10 multilingual patterns (zh, es, fr, de, ja, ko, ru, ar) + XML tag injection + homoglyph detection, merges with built-ins |
| Profile seeder | **REAL** | Pre-seeded behavioral profiles for known MCP servers, loads from JSON bundles, creates `SeededServerProfile` with `learning_mode=true` |

**Verdict: REAL.** All pattern loaders are functional with proper validation and merge logic.

### 10.7 Telemetry

| Item | Classification | Notes |
|------|---------------|-------|
| `ConsentManager` | **REAL** | Opt-in/out persistence, UUID generation for anonymous tracking |
| `TelemetryAggregator` | **REAL** | Collects: blocklist matches, anomaly events, killchain triggers, IoC matches, scanner findings |
| `TelemetryReporter` | **REAL** | Async HTTP submission to configurable endpoint, dry-run mode, disabled by default |
| Privacy guarantees | **REAL** | No file paths, no server names, no IPs, no usernames -- aggregate counts only |

**Verdict: REAL.** Complete opt-in telemetry with strong privacy guarantees.

### 10.8 Feed Data Files

| File | Classification | Notes |
|------|---------------|-------|
| `threat-feed/feed/v1/manifest.json` | **REAL** | Version 1.0.0, references 20+ files with SHA-256 hashes and sizes |
| `threat-feed/feed/v1/blocklist.json` | **REAL** | 12 entries: 4 MaliciousServer, 4 VulnerableServer, 4 CompromisedVersion |
| Blocklist data quality | **PARTIAL** | Entries marked `[SYNTHETIC/TEST]` -- realistic structure but not real threat data |
| Baseline data | **REAL** | `baseline/manifest.json` and `baseline/blocklist.json` embedded via `include_str!` |

**Verdict: REAL structure, PARTIAL data.** Feed infrastructure is complete but blocklist entries are synthetic test data, not real threat intelligence.

### 10.9 Reputation Checking

Reputation checking is implemented through the combination of:
1. **Blocklist matching** -- checks server name, version, hash against known threats
2. **IoC engine** -- checks event data against indicators of compromise
3. **Context tracker** (in SLM crate) -- maintains per-server allowed/blocked/prompted counters

There is no single `reputation_score()` function, but the combination provides comprehensive reputation assessment.

**Verdict: REAL** (distributed across multiple subsystems).

### 10.10 Threat Intelligence Summary

| Subsystem | Classification |
|-----------|---------------|
| Feed client (HTTP + incremental) | **REAL** |
| Ed25519 signature verification | **REAL** (placeholder key) |
| Key rotation support | **REAL** |
| Offline fallback + bundled baseline | **REAL** |
| Blocklist matching engine | **REAL** |
| IoC database + engine | **REAL** |
| Community rule packs | **REAL** |
| Kill chain pattern loader | **REAL** |
| Injection signature loader | **REAL** |
| Behavioral profile seeder | **REAL** |
| Telemetry (opt-in, anonymous) | **REAL** |
| Feed data files | **REAL** structure, **PARTIAL** data (synthetic) |

**Overall Threat Intelligence verdict: REAL.** The crate is production-quality with comprehensive functionality. Two items need attention: (1) the embedded Ed25519 public key is a placeholder (all zeros), and (2) feed data contains synthetic test entries rather than real threat intelligence.

---

## Production Readiness Checklist

### Must-fix before release:
1. **SLM model checksums** -- Replace all-zero SHA-256 placeholders in `model_registry.rs` with real checksums from HuggingFace
2. **Ed25519 public key** -- Replace all-zero placeholder in `signature.rs` with real production key
3. **Threat feed data** -- Replace synthetic `[SYNTHETIC/TEST]` blocklist entries with real threat intelligence

### Recommended improvements:
4. **Model hot-swapping** -- Add a live model swap API to `SlmService` to avoid service reconstruction
5. **Feed signing** -- Set up a signing pipeline to produce Ed25519-signed feed manifests
6. **Checksum automation** -- CI step to verify model registry checksums match HuggingFace releases
