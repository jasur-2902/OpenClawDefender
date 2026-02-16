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

# Alias for release
build-release: release

# Build release and install to /usr/local/bin
install: release
    cp target/release/clawai /usr/local/bin/

# Build release, copy to /usr/local/bin, and run init
install-local: release
    cp target/release/clawai /usr/local/bin/
    clawai init

# Build release tarball and checksum (for local packaging)
package: release
    mkdir -p dist
    cp target/release/clawai dist/clawai
    cd dist && tar czf clawai-macos-$(uname -m).tar.gz clawai
    cd dist && shasum -a 256 clawai-macos-$(uname -m).tar.gz > clawai-macos-$(uname -m).tar.gz.sha256
    @echo "Package created in dist/"

# Run integration tests (builds workspace first, then runs e2e + policy fixture tests)
integration-test:
    cargo build --workspace
    cargo test -p claw-mcp-proxy --test e2e_proxy_test -- --ignored
    cargo test -p claw-core --test mcp_proxy_test

# Clean build artifacts
clean:
    cargo clean
    rm -rf dist

# Build and open documentation
docs:
    cargo doc --workspace --no-deps --open

# Run JSON-RPC fuzzer (requires nightly)
fuzz-jsonrpc:
    cargo +nightly fuzz run fuzz_jsonrpc_parser

# Run policy engine fuzzer (requires nightly)
fuzz-policy:
    cargo +nightly fuzz run fuzz_policy_engine
