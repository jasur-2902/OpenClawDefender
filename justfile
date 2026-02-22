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

# Build the daemon binary
build-daemon:
    cargo build -p clawdefender-daemon

# Build the Tauri GUI app (frontend + backend + daemon)
build-app:
    cargo build -p clawdefender-daemon --release
    cd clients/clawdefender-app && npm install && npm run build
    cd clients/clawdefender-app/src-tauri && cargo build --release

# Run the Tauri GUI app in development mode (builds daemon first)
dev-app:
    cargo build -p clawdefender-daemon -p clawdefender-cli
    cd clients/clawdefender-app/src-tauri && cargo tauri dev

# Copy daemon binary to Tauri sidecar location for bundling
build-sidecar:
    cargo build -p clawdefender-daemon --release
    mkdir -p clients/clawdefender-app/src-tauri/binaries
    cp target/release/clawdefender-daemon clients/clawdefender-app/src-tauri/binaries/clawdefender-daemon-$(rustc -vV | grep host | cut -d' ' -f2)

# Build the .dmg installer
build-dmg:
    cargo build -p clawdefender-daemon --release
    mkdir -p clients/clawdefender-app/src-tauri/binaries
    cp target/release/clawdefender-daemon "clients/clawdefender-app/src-tauri/binaries/clawdefender-daemon-$(rustc -vV | grep host | cut -d' ' -f2)"
    cd clients/clawdefender-app && npm install && cargo tauri build

# Build .dmg for a specific target (e.g., aarch64-apple-darwin or x86_64-apple-darwin)
build-dmg-target TARGET:
    cd clients/clawdefender-app && npm install && cargo tauri build --target {{TARGET}}

# Build the Swift network extension
build-extension:
    cd extensions/clawdefender-network && swift build

# Build workspace + Swift extension
build-all: dev build-extension
    @echo "All components built."

# Run all network-related tests (policy, DNS, logging, integration)
test-network:
    cargo test -p clawdefender-core -- network
    cargo test -p clawdefender-core -- dns
    cargo test -p clawdefender-daemon --test network_integration
    cargo test -p clawdefender-daemon -- mock_network_extension

# Check that everything compiles, passes lints, and tests
preflight: lint test
    @echo "All checks passed."
