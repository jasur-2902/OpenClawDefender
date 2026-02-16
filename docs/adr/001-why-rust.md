# ADR-001: Why Rust

**Status:** Accepted

## Context

ClawAI is a security daemon that sits in the critical path between AI agents and the tools they invoke. It parses untrusted input (JSON-RPC from MCP clients and servers), runs continuously as a background process, and must not itself become an attack vector.

We needed to choose a language for implementing ClawAI that prioritizes correctness, safety, and performance.

## Decision

We chose Rust as the implementation language for ClawAI.

### Rationale

**Memory safety without garbage collection.** ClawAI handles untrusted input in a security-critical context. Memory corruption bugs (buffer overflows, use-after-free, double-free) are the most common class of exploitable vulnerabilities in systems software. Rust eliminates these at compile time without the unpredictable latency of a garbage collector — important for a proxy that sits in the hot path of every tool call.

**Excellent async runtime.** MCP proxy work is inherently I/O-bound: reading from stdin, writing to stdout, waiting on HTTP responses. Tokio provides a mature, performant async runtime that handles this naturally.

**Strong type system.** MCP has a well-defined protocol with specific message types. Rust's type system (enums, pattern matching, serde) lets us model the protocol precisely and catch mishandling at compile time rather than runtime.

**Cross-platform.** ClawAI must work on macOS (primary target with eslogger), Linux, and eventually Windows. Rust compiles to native binaries on all three with no runtime dependencies.

**Growing security tooling ecosystem.** The Rust security ecosystem includes mature crates for JSON parsing (serde_json), TOML (toml), async I/O (tokio), and process management. Cargo's dependency management and `cargo-audit` provide supply chain visibility.

## Consequences

- Contributors must know Rust. This raises the barrier to entry compared to Python or TypeScript.
- Compile times are longer than most languages. Mitigated with incremental compilation and `cargo-nextest` for faster test execution.
- Some OS-specific APIs (eslogger, Endpoint Security) require unsafe FFI. These are isolated in the `clawai-monitor` crate.
