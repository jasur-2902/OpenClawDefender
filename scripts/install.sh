#!/usr/bin/env bash
set -euo pipefail

REPO="clawai/clawai"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="clawai"

echo "Installing ClawAI..."

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    arm64|aarch64)
        echo "Detected architecture: ARM64"
        ;;
    x86_64)
        echo "Detected architecture: x86_64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# Try to download from GitHub Releases
LATEST_TAG=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)

if [ -n "$LATEST_TAG" ]; then
    echo "Downloading ClawAI ${LATEST_TAG}..."
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${BINARY_NAME}"

    if curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${BINARY_NAME}"; then
        chmod +x "/tmp/${BINARY_NAME}"
        sudo mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        echo "ClawAI ${LATEST_TAG} installed to ${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo "Download failed. Building from source..."
        BUILD_FROM_SOURCE=1
    fi
else
    echo "No release found. Building from source..."
    BUILD_FROM_SOURCE=1
fi

if [ "${BUILD_FROM_SOURCE:-0}" = "1" ]; then
    if ! command -v cargo &>/dev/null; then
        echo "Error: Rust toolchain not found. Install it from https://rustup.rs"
        exit 1
    fi

    TMPDIR=$(mktemp -d)
    git clone "https://github.com/${REPO}.git" "$TMPDIR"
    cd "$TMPDIR"
    cargo build --release
    sudo cp "target/release/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf "$TMPDIR"
    echo "ClawAI built from source and installed to ${INSTALL_DIR}/${BINARY_NAME}"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Run 'clawai init' to generate a default policy"
echo "  2. Edit ~/.config/clawai/policy.toml to customize rules"
echo "  3. Run 'clawai --help' for usage information"
