# Contributing to ClawAI

## Build from source

```bash
# Clone the repository
git clone https://github.com/clawai/clawai.git
cd clawai

# Install Rust (if you don't have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install just (task runner)
cargo install just

# Build and run in development mode
just dev

# Run the test suite
just test
```

Requires Rust 1.75+ and macOS 13+ for OS monitoring features (the proxy and policy engine build on Linux and macOS).

## Code style

- **Format:** `rustfmt` defaults. Run `cargo fmt --all` before committing.
- **Lints:** `cargo clippy --all-targets --all-features` must pass with no warnings.
- **Doc comments:** all public APIs must have `///` doc comments. Explain *what* and *why*, not *how*.
- **Error handling:** use `thiserror` for library crates, `anyhow` in the CLI. No `.unwrap()` outside of tests.

## Pull request process

1. Fork the repository and create a feature branch from `main`.
2. Make your changes. Write or update tests as needed.
3. Ensure CI passes: `just check` runs fmt, clippy, and tests.
4. Open a PR against `main` with a clear description of what changed and why.
5. One approval from a maintainer is required to merge.
6. Squash-merge is the default merge strategy.

## Good first issues

Issues labeled [`good first issue`](https://github.com/clawai/clawai/labels/good%20first%20issue) are scoped, well-described tasks suitable for new contributors. They typically involve:

- Adding a new policy rule type
- Improving error messages
- Writing tests for edge cases
- Documentation improvements

If you want to work on one, comment on the issue so others know it's taken.

## Architecture overview for contributors

ClawAI is a Cargo workspace. The dependency graph flows downward:

```
clawai-cli
  ├── clawai-proxy
  │     └── clawai-common
  ├── clawai-policy
  │     └── clawai-common
  ├── clawai-audit
  │     └── clawai-common
  ├── clawai-monitor
  │     └── clawai-common
  └── clawai-correlate
        ├── clawai-audit
        └── clawai-monitor
```

- **clawai-common** defines MCP protocol types, shared error types, and configuration structures. If you're adding a new MCP method, start here.
- **clawai-policy** is where rule evaluation lives. Policies are TOML files parsed into typed Rust structs.
- **clawai-proxy** handles the actual interception — spawning the real MCP server, sitting in the middle of stdio, and forwarding/blocking based on policy decisions.
- **clawai-monitor** wraps `eslogger` and parses its JSON output into typed events.
- **clawai-correlate** joins MCP-layer events with OS-layer events by timestamp and process tree.

See the [ADRs](docs/adr/) for rationale behind key design decisions.
