#!/usr/bin/env bash
set -euo pipefail

REPO="clawai/clawai"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="clawai"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_DL="https://github.com/${REPO}/releases/download"

# --- Helpers ---

info()  { echo "==> $*"; }
error() { echo "ERROR: $*" >&2; exit 1; }

# --- Pre-flight checks ---

if [[ "$(uname -s)" != "Darwin" ]]; then
    error "ClawAI currently supports macOS only. See https://github.com/${REPO} for other platforms."
fi

ARCH="$(uname -m)"
case "$ARCH" in
    arm64|aarch64|x86_64) ;;
    *) error "Unsupported architecture: $ARCH" ;;
esac
info "Detected macOS on $ARCH"

if command -v "$BINARY_NAME" &>/dev/null; then
    EXISTING="$(command -v "$BINARY_NAME")"
    EXISTING_VER="$("$BINARY_NAME" --version 2>/dev/null || echo "unknown")"
    info "Existing installation found: $EXISTING ($EXISTING_VER)"
    info "It will be replaced."
fi

# --- Resolve latest release ---

info "Fetching latest release from GitHub..."
LATEST_TAG="$(curl -fsSL "$GITHUB_API" | grep '"tag_name"' | cut -d'"' -f4)" \
    || error "Failed to fetch latest release. Check your network connection."

if [[ -z "$LATEST_TAG" ]]; then
    error "Could not determine latest release tag."
fi

info "Latest release: $LATEST_TAG"

# --- Download ---

TARBALL="clawai-macos-universal.tar.gz"
DOWNLOAD_URL="${GITHUB_DL}/${LATEST_TAG}/${TARBALL}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${TARBALL}..."
curl -fSL --progress-bar "$DOWNLOAD_URL" -o "$TMPDIR/$TARBALL" \
    || error "Download failed. URL: $DOWNLOAD_URL"

info "Downloading checksum..."
curl -fsSL "$CHECKSUM_URL" -o "$TMPDIR/${TARBALL}.sha256" \
    || error "Checksum download failed."

# --- Verify checksum ---

info "Verifying SHA-256 checksum..."
EXPECTED="$(awk '{print $1}' "$TMPDIR/${TARBALL}.sha256")"
ACTUAL="$(shasum -a 256 "$TMPDIR/$TARBALL" | awk '{print $1}')"

if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    error "Checksum mismatch!\n  Expected: $EXPECTED\n  Actual:   $ACTUAL\nThe download may be corrupted. Please try again."
fi

info "Checksum verified."

# --- Install ---

info "Extracting..."
tar xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"
chmod +x "$TMPDIR/$BINARY_NAME"

info "Installing to $INSTALL_DIR (may require sudo)..."
if [[ -w "$INSTALL_DIR" ]]; then
    mv "$TMPDIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
else
    sudo mv "$TMPDIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
fi

# --- Initialize ---

info "Running 'clawai init'..."
"$INSTALL_DIR/$BINARY_NAME" init || true

# --- Done ---

echo ""
echo "ClawAI $LATEST_TAG installed successfully!"
echo ""
echo "Next steps:"
echo "  clawai wrap <server-name>   Protect an MCP server"
echo "  clawai status               Check proxy status"
echo "  clawai --help               Full usage information"
echo ""
echo "Configuration: ~/.config/clawai/"
echo "Audit logs:    ~/.local/share/clawai/"
