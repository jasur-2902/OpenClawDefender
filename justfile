# ClawAI development commands

# Build all crates in debug mode
dev:
    cargo build --workspace

# Run all tests
test:
    cargo test --workspace

# Run lints (format check + clippy)
lint:
    cargo fmt --check
    cargo clippy --workspace -- -D warnings

# Run security audits
audit:
    cargo audit
    cargo deny check

# Build all crates in release mode
release:
    cargo build --workspace --release

# Build release and install to /usr/local/bin
install: release
    cp target/release/clawai /usr/local/bin/

# Clean build artifacts
clean:
    cargo clean

# Build and open documentation
docs:
    cargo doc --workspace --no-deps --open

# Run JSON-RPC fuzzer (requires nightly)
fuzz-jsonrpc:
    cargo +nightly fuzz run fuzz_jsonrpc_parser

# Run policy engine fuzzer (requires nightly)
fuzz-policy:
    cargo +nightly fuzz run fuzz_policy_engine
