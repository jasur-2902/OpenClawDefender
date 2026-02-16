#!/usr/bin/env bash
# ============================================================================
# OpenClawDefender - Integration Test Suite
# ============================================================================
#
# Validates the built binaries, configuration, and service installation.
# This script is designed to run inside a Linux environment (Docker or VM).
#
# Usage:
#   sudo bash tests/integration_test.sh
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo ""
echo "=== OpenClawDefender Integration Tests ==="
echo ""

# -- Test 1: eBPF binary exists ----------------------------------------------

EBPF_BIN="target/bpfel-unknown-none/debug/claw-wall-ebpf"
if [ -f "$EBPF_BIN" ]; then
    log_pass "eBPF binary exists: $EBPF_BIN"
    SIZE=$(stat -c%s "$EBPF_BIN" 2>/dev/null || stat -f%z "$EBPF_BIN" 2>/dev/null || echo "unknown")
    log_info "  Size: $SIZE bytes"
else
    log_fail "eBPF binary not found: $EBPF_BIN"
fi

# -- Test 2: Daemon binary exists ---------------------------------------------

DAEMON_BIN="target/debug/claw-wall"
if [ -f "$DAEMON_BIN" ]; then
    log_pass "Daemon binary exists: $DAEMON_BIN"
else
    log_fail "Daemon binary not found: $DAEMON_BIN"
fi

# -- Test 3: CLI --help -------------------------------------------------------

if [ -f "$DAEMON_BIN" ]; then
    if "$DAEMON_BIN" --help >/dev/null 2>&1; then
        log_pass "claw-wall --help works"
    else
        log_fail "claw-wall --help failed"
    fi
fi

# -- Test 4: --install-service ------------------------------------------------

if [ -f "$DAEMON_BIN" ] && [ "$(id -u)" -eq 0 ]; then
    if "$DAEMON_BIN" --install-service 2>/dev/null; then
        log_pass "--install-service succeeded"
    else
        log_fail "--install-service failed"
    fi

    if [ -f /etc/systemd/system/claw-wall.service ]; then
        log_pass "systemd unit file created"
    else
        log_fail "systemd unit file not found"
    fi
else
    log_info "Skipping --install-service test (not root or binary missing)"
fi

# -- Test 5: --configure (piped input) ----------------------------------------

if [ -f "$DAEMON_BIN" ] && [ "$(id -u)" -eq 0 ]; then
    echo "integration-test-key-12345" | "$DAEMON_BIN" --configure 2>/dev/null
    if [ -f /etc/claw-wall/config.toml ]; then
        log_pass "config file created"

        PERMS=$(stat -c '%a' /etc/claw-wall/config.toml 2>/dev/null || echo "unknown")
        if [ "$PERMS" = "600" ]; then
            log_pass "config file permissions: 600"
        else
            log_fail "config file permissions: $PERMS (expected 600)"
        fi

        if grep -q "integration-test-key-12345" /etc/claw-wall/config.toml 2>/dev/null; then
            log_pass "config contains API key"
        else
            log_fail "config does not contain expected API key"
        fi
    else
        log_fail "config file not created"
    fi
else
    log_info "Skipping --configure test (not root or binary missing)"
fi

# -- Results ------------------------------------------------------------------

echo ""
echo "========================================"
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "========================================"

exit "$FAIL"
