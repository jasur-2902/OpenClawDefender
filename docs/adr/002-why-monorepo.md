# ADR-002: Why Monorepo

**Status:** Accepted

## Context

ClawAI consists of multiple components: a CLI, a proxy, a policy engine, an audit logger, an OS monitor, and a correlation engine. We needed to decide whether to organize these as separate repositories or as a single monorepo.

## Decision

We use a single repository with a Cargo workspace containing multiple crates.

### Rationale

**Shared types across crates.** The MCP protocol types, error types, and configuration structures are used by nearly every component. A monorepo with a `clawai-common` crate makes sharing trivial — no version coordination, no publishing to a registry, no diamond dependency problems.

**Atomic versioning.** A security tool needs consistent versions. When the policy engine changes how it evaluates rules, the proxy, CLI, and tests must all update together. A monorepo guarantees that `main` is always internally consistent.

**Easier for contributors.** A new contributor clones one repo, runs `just dev`, and has everything. No need to clone multiple repos, set up cross-repo linking, or wonder which version of which component they need.

**Cargo workspaces handle this natively.** Rust's tooling is built for this pattern. `cargo build`, `cargo test`, and `cargo clippy` operate on the entire workspace. Dependencies are deduplicated. It just works.

## Consequences

- The repository will grow larger over time. Mitigated by Cargo's incremental compilation — you only rebuild what changed.
- CI runs all tests on every PR, even for changes that only affect one crate. Acceptable for correctness; can be optimized later with path-based CI filtering.
- All crates share the same release cadence. This is intentional for a security tool where version consistency matters.
