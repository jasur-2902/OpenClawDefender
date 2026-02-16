#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="clawdefender"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="${HOME}/.config/clawdefender"
DATA_DIR="${HOME}/.local/share/clawdefender"
PLIST_PATH="${HOME}/Library/LaunchAgents/com.clawdefender.daemon.plist"

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }

echo "ClawDefender Uninstaller"
echo "==================="
echo ""

# --- Unwrap servers ---

if command -v "$BINARY_NAME" &>/dev/null; then
    read -rp "Unwrap all currently wrapped MCP servers before removing? [Y/n] " answer
    if [[ ! "$answer" =~ ^[Nn]$ ]]; then
        info "Unwrapping all servers..."
        "$BINARY_NAME" unwrap --all 2>/dev/null || warn "Could not unwrap servers (none wrapped or command not available)."
    fi
fi

# --- Stop and remove LaunchAgent ---

if [[ -f "$PLIST_PATH" ]]; then
    info "Stopping ClawDefender daemon..."
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"
    info "Removed LaunchAgent."
fi

# --- Remove binary ---

if [[ -f "${INSTALL_DIR}/${BINARY_NAME}" ]]; then
    info "Removing ${INSTALL_DIR}/${BINARY_NAME}..."
    if [[ -w "$INSTALL_DIR" ]]; then
        rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    else
        sudo rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    info "Binary removed."
else
    warn "Binary not found at ${INSTALL_DIR}/${BINARY_NAME}"
fi

# --- Optionally remove config ---

if [[ -d "$CONFIG_DIR" ]]; then
    read -rp "Remove configuration at ${CONFIG_DIR}? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        info "Removed ${CONFIG_DIR}"
    else
        info "Kept ${CONFIG_DIR}"
    fi
fi

# --- Optionally remove audit logs ---

if [[ -d "$DATA_DIR" ]]; then
    read -rp "Remove audit logs at ${DATA_DIR}? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        info "Removed ${DATA_DIR}"
    else
        info "Kept ${DATA_DIR}"
    fi
fi

echo ""
echo "ClawDefender has been uninstalled."
