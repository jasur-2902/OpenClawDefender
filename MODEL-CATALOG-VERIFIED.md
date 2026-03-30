# Model Catalog Verification Report

**Date:** 2026-03-29
**Source file:** `crates/clawdefender-slm/src/model_registry.rs`
**Verified by:** Agent 1 (Model Registry Auditor)

---

## Local GGUF Models (5 total)

### 1. Qwen3 1.7B (qwen3-1.7b-q4) -- DEFAULT

| Field | Registry Value | Verified Value | Status |
|-------|---------------|----------------|--------|
| Download URL | `https://huggingface.co/unsloth/Qwen3-1.7B-GGUF/resolve/main/Qwen3-1.7B-Q4_K_M.gguf` | HTTP 302 redirect to CDN | PASS |
| File size (bytes) | 1,107,409,472 | `x-linked-size: 1107409472` | MATCH |
| SHA-256 | `b139949c5bd74937ad8ed8c8cf3d9ffb1e99c866c823204dc42c0d91fa181897` | `x-linked-etag` matches | MATCH |
| Quantization | Q4_K_M | Correct for filename | PASS |
| min_ram_gb | 4 | ~1.1GB file, 4GB reasonable for 1.7B model | PASS |
| ram_required_bytes | 4 GiB (4,294,967,296) | Consistent with min_ram_gb | PASS |
| Author | Alibaba/Qwen | Correct (unsloth quantization of Qwen model) | PASS |

### 2. Qwen3 4B (qwen3-4b-q4)

| Field | Registry Value | Verified Value | Status |
|-------|---------------|----------------|--------|
| Download URL | `https://huggingface.co/Qwen/Qwen3-4B-GGUF/resolve/main/Qwen3-4B-Q4_K_M.gguf` | HTTP 302 redirect to CDN | PASS |
| File size (bytes) | 2,497,280,256 | `x-linked-size: 2497280256` | MATCH |
| SHA-256 | `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5` | `x-linked-etag` matches | MATCH |
| Quantization | Q4_K_M | Correct for filename | PASS |
| min_ram_gb | 8 | ~2.5GB file, 8GB reasonable for 4B model | PASS |
| ram_required_bytes | 8 GiB (8,589,934,592) | Consistent with min_ram_gb | PASS |
| Author | Alibaba/Qwen | Correct (official Qwen repo) | PASS |

### 3. Phi-4 Mini Instruct 3.8B (phi4-mini-3.8b-q4)

| Field | Registry Value | Verified Value | Status |
|-------|---------------|----------------|--------|
| Download URL | `https://huggingface.co/unsloth/Phi-4-mini-instruct-GGUF/resolve/main/Phi-4-mini-instruct-Q4_K_M.gguf` | HTTP 302 redirect to CDN | PASS |
| File size (bytes) | 2,491,874,272 | `x-linked-size: 2491874272` | MATCH |
| SHA-256 | `88c00229914083cd112853aab84ed51b87bdf6b9ce42f532d8c85c7c63b1730a` | `x-linked-etag` matches | MATCH |
| Quantization | Q4_K_M | Correct for filename | PASS |
| min_ram_gb | 8 | ~2.5GB file, 8GB reasonable for 3.8B model | PASS |
| ram_required_bytes | 8 GiB (8,589,934,592) | Consistent with min_ram_gb | PASS |
| Author | Microsoft | Correct | PASS |

### 4. Gemma 3 1B (gemma3-1b-q4)

| Field | Registry Value | Verified Value | Status |
|-------|---------------|----------------|--------|
| Download URL | `https://huggingface.co/ggml-org/gemma-3-1b-it-GGUF/resolve/main/gemma-3-1b-it-Q4_K_M.gguf` | HTTP 302 redirect to CDN | PASS |
| File size (bytes) | 806,058,240 | `x-linked-size: 806058240` | MATCH |
| SHA-256 | `8ccc5cd1f1b3602548715ae25a66ed73fd5dc68a210412eea643eb20eb75a135` | `x-linked-etag` matches | MATCH |
| Quantization | Q4_K_M | Correct for filename | PASS |
| min_ram_gb | 2 | ~806MB file, 2GB reasonable for 1B model | PASS |
| ram_required_bytes | 2 GiB (2,147,483,648) | Consistent with min_ram_gb | PASS |
| Author | Google | Correct (ggml-org quantization of Google model) | PASS |

### 5. Gemma 3 4B (gemma3-4b-q4)

| Field | Registry Value | Verified Value | Status |
|-------|---------------|----------------|--------|
| Download URL | `https://huggingface.co/ggml-org/gemma-3-4b-it-GGUF/resolve/main/gemma-3-4b-it-Q4_K_M.gguf` | HTTP 302 redirect to CDN | PASS |
| File size (bytes) | 2,489,757,856 | `x-linked-size: 2489757856` | MATCH |
| SHA-256 | `882e8d2db44dc554fb0ea5077cb7e4bc49e7342a1f0da57901c0802ea21a0863` | `x-linked-etag` matches | MATCH |
| Quantization | Q4_K_M | Correct for filename | PASS |
| min_ram_gb | 8 | ~2.5GB file, 8GB reasonable for 4B model | PASS |
| ram_required_bytes | 8 GiB (8,589,934,592) | Consistent with min_ram_gb | PASS |
| Author | Google | Correct (ggml-org quantization of Google model) | PASS |

---

## Cloud Provider Models (3 providers, 6 models)

### Anthropic

| Model ID | Display Name | Valid? | Pricing (per 1K tokens) | Notes |
|----------|-------------|--------|--------------------------|-------|
| `claude-sonnet-4-20250514` | Claude Sonnet 4 | YES | $0.003 in / $0.015 out | Valid legacy model, matches official docs |
| `claude-haiku-4-5-20251001` | Claude Haiku 4.5 | YES | $0.001 in / $0.005 out | **FIXED** -- was `claude-haiku-4-20250506` (invalid ID) |

### OpenAI

| Model ID | Display Name | Valid? | Pricing (per 1K tokens) | Notes |
|----------|-------------|--------|--------------------------|-------|
| `gpt-4o-mini` | GPT-4o Mini | YES | $0.00015 in / $0.0006 out | Still available in API |
| `gpt-4o` | GPT-4o | YES | $0.0025 in / $0.01 out | Retired from ChatGPT but still in API |

### Google

| Model ID | Display Name | Valid? | Pricing (per 1K tokens) | Notes |
|----------|-------------|--------|--------------------------|-------|
| `gemini-2.0-flash` | Gemini Flash | DEPRECATED | $0.0001 in / $0.0004 out | Shutting down June 1, 2026 -- consider updating to `gemini-2.5-flash` |
| `gemini-2.5-pro` | Gemini Pro | YES | $0.00125 in / $0.01 out | Valid |

---

## Fixes Applied

1. **claude-haiku-4-20250506 -> claude-haiku-4-5-20251001**: The old model ID `claude-haiku-4-20250506` was invalid. Anthropic never released a "Claude Haiku 4". The correct model is Claude Haiku 4.5 with ID `claude-haiku-4-5-20251001`. Display name updated to "Claude Haiku 4.5", pricing updated to $1/$5 per MTok.

## Warnings

1. **gemini-2.0-flash deprecation**: Google has announced that `gemini-2.0-flash` will be shut down on June 1, 2026. A future update should migrate to `gemini-2.5-flash` or `gemini-2.5-flash-lite` before that date.

---

## Verification Methodology

- **URL verification**: Used `curl -sI` (HTTP HEAD) against each HuggingFace download URL. All returned HTTP 302 redirects to CDN, which is normal behavior.
- **File size verification**: Compared `x-linked-size` header from HuggingFace response against `size_bytes` in registry.
- **SHA-256 verification**: Compared `x-linked-etag` header (which HuggingFace uses for SHA-256 hashes of GGUF files) against `sha256` in registry.
- **Cloud model verification**: Cross-referenced model IDs against official API documentation from Anthropic, OpenAI, and Google.
- **RAM requirements**: Validated that min_ram_gb and ram_required_bytes are consistent and reasonable (typically 2-3x the model file size for inference overhead).
- **Tests**: All 17 model_registry unit tests pass after fixes.
