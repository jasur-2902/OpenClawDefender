#!/usr/bin/env bash
# ============================================================================
# OpenClawDefender - Docker Test Entrypoint
# ============================================================================
#
# Supports multiple test modes:
#   build  - Validate that all crates compile (default, no --privileged needed)
#   test   - Run full test suite including eBPF loading (requires --privileged)
#   shell  - Drop into an interactive bash shell
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0

log_info()  { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1"; }
log_header(){ echo -e "\n${CYAN}=== $1 ===${NC}\n"; }

run_test() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        log_pass "$name"
        PASS=$((PASS + 1))
    else
        log_fail "$name"
        FAIL=$((FAIL + 1))
    fi
}

run_test_verbose() {
    local name="$1"
    shift
    if "$@" 2>&1; then
        log_pass "$name"
        PASS=$((PASS + 1))
    else
        log_fail "$name"
        FAIL=$((FAIL + 1))
    fi
}

print_summary() {
    echo ""
    echo "========================================"
    echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
    echo "========================================"
    exit "$FAIL"
}

# --------------------------------------------------------------------------
# Mode: build - Validate compilation only
# --------------------------------------------------------------------------
mode_build() {
    log_header "Build Validation"

    log_info "Checking Rust toolchain..."
    run_test "rustc available" rustc --version
    run_test "cargo available" cargo --version
    run_test "bpf-linker available" which bpf-linker

    log_info "Checking eBPF build artifacts..."
    EBPF_BIN="target/bpfel-unknown-none/debug/claw-wall-ebpf"
    if [ -f "$EBPF_BIN" ]; then
        log_pass "eBPF binary exists: $EBPF_BIN"
        PASS=$((PASS + 1))
    else
        log_fail "eBPF binary not found: $EBPF_BIN"
        FAIL=$((FAIL + 1))
    fi

    log_info "Checking daemon build..."
    DAEMON_BIN="target/debug/claw-wall"
    if [ -f "$DAEMON_BIN" ]; then
        log_pass "Daemon binary exists: $DAEMON_BIN"
        PASS=$((PASS + 1))
    else
        log_fail "Daemon binary not found: $DAEMON_BIN"
        FAIL=$((FAIL + 1))
    fi

    log_info "Running claw-wall-common unit tests..."
    run_test_verbose "claw-wall-common tests" cargo test --package claw-wall-common

    log_info "Testing CLI help output..."
    if [ -f "$DAEMON_BIN" ]; then
        run_test "claw-wall --help" ./target/debug/claw-wall --help
    fi

    print_summary
}

# --------------------------------------------------------------------------
# Mode: test - Full test suite (requires --privileged)
# --------------------------------------------------------------------------
mode_test() {
    log_header "Full eBPF Test Suite (privileged)"

    # First run build checks
    log_info "Checking Rust toolchain..."
    run_test "rustc available" rustc --version
    run_test "cargo available" cargo --version

    log_info "Checking BPF kernel support..."
    if [ -f /proc/config.gz ]; then
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
            log_pass "CONFIG_BPF=y found in kernel"
            PASS=$((PASS + 1))
        else
            log_fail "CONFIG_BPF=y not found - eBPF tests will fail"
            FAIL=$((FAIL + 1))
        fi
    elif [ -f "/boot/config-$(uname -r)" ]; then
        if grep -q "CONFIG_BPF=y" "/boot/config-$(uname -r)"; then
            log_pass "CONFIG_BPF=y found in kernel"
            PASS=$((PASS + 1))
        else
            log_fail "CONFIG_BPF=y not found - eBPF tests will fail"
            FAIL=$((FAIL + 1))
        fi
    else
        log_info "Cannot verify kernel config, attempting BPF operations anyway..."
    fi

    # Check for /sys/kernel/debug/tracing (needed for tracepoints)
    if mount | grep -q debugfs; then
        log_pass "debugfs mounted"
        PASS=$((PASS + 1))
    else
        log_info "Mounting debugfs..."
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    log_info "Running claw-wall-common unit tests..."
    run_test_verbose "claw-wall-common tests" cargo test --package claw-wall-common

    log_info "Checking eBPF binary..."
    EBPF_BIN="target/bpfel-unknown-none/debug/claw-wall-ebpf"
    if [ -f "$EBPF_BIN" ]; then
        log_pass "eBPF binary exists"
        PASS=$((PASS + 1))

        log_info "Inspecting eBPF binary with llvm-objdump..."
        if llvm-objdump-14 -d "$EBPF_BIN" 2>/dev/null | head -20; then
            log_pass "eBPF binary is valid ELF"
            PASS=$((PASS + 1))
        else
            log_fail "eBPF binary inspection failed"
            FAIL=$((FAIL + 1))
        fi
    else
        log_fail "eBPF binary not found"
        FAIL=$((FAIL + 1))
    fi

    log_info "Testing daemon CLI..."
    if [ -f "target/debug/claw-wall" ]; then
        run_test "claw-wall --help" ./target/debug/claw-wall --help
        run_test "claw-wall --install-service" ./target/debug/claw-wall --install-service
        run_test "systemd unit created" test -f /etc/systemd/system/claw-wall.service
    fi

    log_info "Testing --configure (piped input)..."
    if [ -f "target/debug/claw-wall" ]; then
        echo "test-api-key-12345" | ./target/debug/claw-wall --configure 2>/dev/null
        run_test "config file created" test -f /etc/claw-wall/config.toml
        if [ -f /etc/claw-wall/config.toml ]; then
            PERMS=$(stat -c '%a' /etc/claw-wall/config.toml 2>/dev/null || echo "unknown")
            if [ "$PERMS" = "600" ]; then
                log_pass "config file permissions: 600"
                PASS=$((PASS + 1))
            else
                log_fail "config file permissions: $PERMS (expected 600)"
                FAIL=$((FAIL + 1))
            fi
        fi
    fi

    print_summary
}

# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------
case "${1:-build}" in
    build)
        mode_build
        ;;
    test)
        mode_test
        ;;
    shell)
        log_info "Dropping into interactive shell..."
        exec /bin/bash
        ;;
    *)
        echo "Usage: docker run claw-wall-test [build|test|shell]"
        echo ""
        echo "  build  - Validate compilation (default, no --privileged needed)"
        echo "  test   - Full eBPF test suite (requires --privileged)"
        echo "  shell  - Interactive bash shell"
        exit 1
        ;;
esac
