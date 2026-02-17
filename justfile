# ClawDefender development commands

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

# Build release and install both binaries to /usr/local/bin
install: release
    cp target/release/clawdefender /usr/local/bin/
    cp target/release/clawdefender-daemon /usr/local/bin/

# Build release, install to /usr/local/bin, and run init
install-local: release
    cp target/release/clawdefender /usr/local/bin/
    cp target/release/clawdefender-daemon /usr/local/bin/
    clawdefender init

# Build release tarball and checksum (for local packaging)
package: release
    mkdir -p dist
    cp target/release/clawdefender dist/clawdefender
    cp target/release/clawdefender-daemon dist/clawdefender-daemon
    cd dist && tar czf clawdefender-macos-$(uname -m).tar.gz clawdefender clawdefender-daemon
    cd dist && shasum -a 256 clawdefender-macos-$(uname -m).tar.gz > clawdefender-macos-$(uname -m).tar.gz.sha256
    @echo "Package created in dist/"

# Run integration tests (builds workspace first, then runs e2e + policy fixture tests)
integration-test:
    cargo build --workspace
    cargo test -p clawdefender-mcp-proxy --test e2e_proxy_test -- --ignored
    cargo test -p clawdefender-core --test mcp_proxy_test

# Clean build artifacts
clean:
    cargo clean
    rm -rf dist

# Build and open documentation
docs:
    cargo doc --workspace --no-deps --open

# Build macOS menu bar app
build-menubar:
    cd clients/clawdefender-menubar && swift build

# Run JSON-RPC fuzzer (requires nightly)
fuzz-jsonrpc:
    cargo +nightly fuzz run fuzz_jsonrpc_parser

# Run policy engine fuzzer (requires nightly)
fuzz-policy:
    cargo +nightly fuzz run fuzz_policy_engine

# Bump version across all Cargo.toml files
bump-version VERSION:
    sed -i '' 's/^version = ".*"/version = "{{VERSION}}"/' Cargo.toml
    @echo "Version bumped to {{VERSION}} in workspace Cargo.toml"
    @echo "Remember to update Formula/clawdefender.rb version too."

# Check that everything compiles, passes lints, and tests
preflight: lint test
    @echo "All checks passed."
