#!/bin/bash
set -euo pipefail

# OpenClawDefender eBPF Firewall Installer

BINARY_NAME="claw-wall"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/claw-wall"
SERVICE_FILE="claw-wall.service"
SYSTEMD_DIR="/etc/systemd/system"
LOCAL_BUILD_PATH="./target/release/${BINARY_NAME}"

info() {
    printf '[INFO]  %s\n' "$1"
}

error() {
    printf '[ERROR] %s\n' "$1" >&2
    exit 1
}

warn() {
    printf '[WARN]  %s\n' "$1"
}

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
    error "This installer must be run as root. Please re-run with: sudo $0"
fi

# --- Architecture detection ---
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)
        info "Detected architecture: x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        info "Detected architecture: aarch64"
        ;;
    *)
        error "Unsupported architecture: ${ARCH}. Only x86_64 and aarch64 are supported."
        ;;
esac

# --- systemd check ---
if ! command -v systemctl >/dev/null 2>&1; then
    error "systemd is required but systemctl was not found. OpenClawDefender requires a systemd-based Linux distribution."
fi

# --- Kernel headers / BPF support check ---
KERNEL_VERSION="$(uname -r)"
info "Kernel version: ${KERNEL_VERSION}"

if [ -d "/lib/modules/${KERNEL_VERSION}/build" ] || [ -d "/usr/src/linux-headers-${KERNEL_VERSION}" ]; then
    info "Kernel headers found."
else
    warn "Kernel headers not found at /lib/modules/${KERNEL_VERSION}/build or /usr/src/linux-headers-${KERNEL_VERSION}."
    warn "eBPF programs may fail to load. Install kernel headers with your package manager:"
    warn "  Debian/Ubuntu: apt install linux-headers-${KERNEL_VERSION}"
    warn "  Fedora/RHEL:   dnf install kernel-devel-${KERNEL_VERSION}"
fi

if [ -f /proc/config.gz ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
        info "BPF support confirmed in kernel config."
    else
        warn "Could not confirm CONFIG_BPF=y in kernel config. eBPF may not work."
    fi
elif [ -f "/boot/config-${KERNEL_VERSION}" ]; then
    if grep -q "CONFIG_BPF=y" "/boot/config-${KERNEL_VERSION}"; then
        info "BPF support confirmed in kernel config."
    else
        warn "Could not confirm CONFIG_BPF=y in kernel config. eBPF may not work."
    fi
else
    warn "Could not locate kernel config to verify BPF support. Proceeding anyway."
fi

# --- Create config directory ---
info "Creating configuration directory at ${CONFIG_DIR}..."
mkdir -p "${CONFIG_DIR}"
chmod 700 "${CONFIG_DIR}"

# --- Install binary ---
if [ ! -f "${LOCAL_BUILD_PATH}" ]; then
    error "Pre-compiled binary not found at ${LOCAL_BUILD_PATH}. Please build the project first with: cargo build --release"
fi

info "Installing ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}..."
cp "${LOCAL_BUILD_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"

# --- Install systemd service ---
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -f "${SCRIPT_DIR}/${SERVICE_FILE}" ]; then
    error "Service file ${SERVICE_FILE} not found in ${SCRIPT_DIR}."
fi

info "Installing systemd service..."
cp "${SCRIPT_DIR}/${SERVICE_FILE}" "${SYSTEMD_DIR}/${SERVICE_FILE}"
chmod 644 "${SYSTEMD_DIR}/${SERVICE_FILE}"

# --- Enable and start service ---
info "Reloading systemd daemon..."
systemctl daemon-reload

info "Enabling ${BINARY_NAME} service..."
systemctl enable "${BINARY_NAME}.service"

info "Starting ${BINARY_NAME} service..."
systemctl start "${BINARY_NAME}.service"

# --- Success ---
printf '\n'
info "============================================"
info " OpenClawDefender installed successfully!"
info "============================================"
printf '\n'
info "Binary:  ${INSTALL_DIR}/${BINARY_NAME}"
info "Config:  ${CONFIG_DIR}/"
info "Service: ${SYSTEMD_DIR}/${SERVICE_FILE}"
printf '\n'
info "Next steps:"
info "  1. Configure the firewall:  claw-wall --configure"
info "  2. Check service status:    systemctl status ${BINARY_NAME}"
info "  3. View logs:               journalctl -u ${BINARY_NAME} -f"
printf '\n'
