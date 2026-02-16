#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="clawai"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="${HOME}/.config/clawai"
DATA_DIR="${HOME}/.local/share/clawai"

echo "Uninstalling ClawAI..."

# Remove binary
if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
    sudo rm "${INSTALL_DIR}/${BINARY_NAME}"
    echo "Removed ${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Binary not found at ${INSTALL_DIR}/${BINARY_NAME}"
fi

# Optionally remove config
if [ -d "$CONFIG_DIR" ]; then
    read -rp "Remove configuration at ${CONFIG_DIR}? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo "Removed ${CONFIG_DIR}"
    fi
fi

# Optionally remove audit logs
if [ -d "$DATA_DIR" ]; then
    read -rp "Remove audit logs at ${DATA_DIR}? [y/N] " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        rm -rf "$DATA_DIR"
        echo "Removed ${DATA_DIR}"
    fi
fi

echo "ClawAI uninstalled."
