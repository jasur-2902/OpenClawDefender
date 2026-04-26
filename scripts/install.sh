#!/usr/bin/env bash
set -euo pipefail

REPO="rookbot-io/rookbot"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="rookbot"
DAEMON_NAME="rookbot-daemon"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"
GITHUB_DL="https://github.com/${REPO}/releases/download"

# --- Helpers ---

info()  { echo "==> $*"; }
error() { echo "ERROR: $*" >&2; exit 1; }

# --- Detect platform ---

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin)
        PLATFORM="macos"
        MACOS_VER="$(sw_vers -productVersion 2>/dev/null || echo "0")"
        MACOS_MAJOR="$(echo "$MACOS_VER" | cut -d. -f1)"
        if [[ "$MACOS_MAJOR" -lt 13 ]]; then
            error "Rookbot requires macOS 13 (Ventura) or later. You have macOS $MACOS_VER."
        fi
        TARBALL="rookbot-macos-universal.tar.gz"
        info "Detected macOS $MACOS_VER on $ARCH"
        ;;
    Linux)
        PLATFORM="linux"
        case "$ARCH" in
            x86_64)  TARBALL="rookbot-linux-x86_64.tar.gz" ;;
            aarch64) TARBALL="rookbot-linux-aarch64.tar.gz" ;;
            *)       error "Unsupported Linux architecture: $ARCH" ;;
        esac
        info "Detected Linux on $ARCH"
        ;;
    *)
        error "Unsupported operating system: $OS. Rookbot supports macOS and Linux."
        ;;
esac

case "$ARCH" in
    arm64|aarch64|x86_64) ;;
    *) error "Unsupported architecture: $ARCH" ;;
esac

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

if command -v sha256sum &>/dev/null; then
    ACTUAL="$(sha256sum "$TMPDIR/$TARBALL" | awk '{print $1}')"
else
    ACTUAL="$(shasum -a 256 "$TMPDIR/$TARBALL" | awk '{print $1}')"
fi

if [[ "$EXPECTED" != "$ACTUAL" ]]; then
    error "Checksum mismatch!\n  Expected: $EXPECTED\n  Actual:   $ACTUAL\nThe download may be corrupted. Please try again."
fi

info "Checksum verified."

# --- Install ---

info "Extracting..."
tar xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"
chmod +x "$TMPDIR/$BINARY_NAME"
chmod +x "$TMPDIR/$DAEMON_NAME" 2>/dev/null || true

info "Installing to $INSTALL_DIR (may require sudo)..."
if [[ -w "$INSTALL_DIR" ]]; then
    mv "$TMPDIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    if [[ -f "$TMPDIR/$DAEMON_NAME" ]]; then
        mv "$TMPDIR/$DAEMON_NAME" "$INSTALL_DIR/$DAEMON_NAME"
    fi
else
    sudo mv "$TMPDIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    if [[ -f "$TMPDIR/$DAEMON_NAME" ]]; then
        sudo mv "$TMPDIR/$DAEMON_NAME" "$INSTALL_DIR/$DAEMON_NAME"
    fi
fi

# --- Initialize ---

info "Running 'rookbot init'..."
"$INSTALL_DIR/$BINARY_NAME" init || true

# --- Done ---

echo ""
echo "Rookbot $LATEST_TAG installed successfully!"
echo ""
echo "Next steps:"
echo "  rookbot wrap <server-name>   Protect an MCP server"
echo "  rookbot status               Check proxy status"
echo "  rookbot --help               Full usage information"
echo ""
echo "Configuration: ~/.config/rookbot/"
echo "Audit logs:    ~/.local/share/rookbot/"
