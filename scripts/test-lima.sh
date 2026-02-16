#!/usr/bin/env bash
# ============================================================================
# OpenClawDefender - Lima VM Test Runner for macOS
# ============================================================================
#
# Uses Lima to create a lightweight Linux VM with full BPF kernel support.
# Lima is the recommended approach for eBPF development on macOS because
# it provides a real Linux kernel (unlike Docker's limited BPF support).
#
# Prerequisites:
#   brew install lima
#
# Usage:
#   ./scripts/test-lima.sh                 # Full test run (provision + build + test)
#   ./scripts/test-lima.sh --no-provision  # Skip VM provisioning (VM already set up)
#   ./scripts/test-lima.sh --shell         # SSH into the VM
#   ./scripts/test-lima.sh --destroy       # Destroy the VM after tests
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

VM_NAME="claw-wall"
LIMA_CONFIG="$PROJECT_DIR/lima.yaml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SKIP_PROVISION=false
DESTROY_AFTER=false
SHELL_ONLY=false

PASS=0
FAIL=0

for arg in "$@"; do
    case "$arg" in
        --no-provision) SKIP_PROVISION=true ;;
        --destroy)      DESTROY_AFTER=true ;;
        --shell)        SHELL_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-provision  Skip VM provisioning (VM already running)"
            echo "  --shell         Just SSH into the VM"
            echo "  --destroy       Destroy VM after tests"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
    esac
done

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

run_test() {
    local name="$1"
    shift
    if "$@"; then
        log_pass "$name"
        PASS=$((PASS + 1))
    else
        log_fail "$name"
        FAIL=$((FAIL + 1))
    fi
}

lima_exec() {
    limactl shell "$VM_NAME" "$@"
}

cd "$PROJECT_DIR"

# -- Preflight ---------------------------------------------------------------

if ! command -v limactl >/dev/null 2>&1; then
    log_fail "Lima is not installed"
    echo ""
    echo "Install Lima:"
    echo "  brew install lima"
    exit 1
fi

# -- Start or create VM ------------------------------------------------------

if [ "$SKIP_PROVISION" = false ]; then
    VM_STATUS=$(limactl list --format '{{.Name}}:{{.Status}}' 2>/dev/null | grep "^${VM_NAME}:" | cut -d: -f2 || echo "")

    if [ "$VM_STATUS" = "Running" ]; then
        log_info "VM '$VM_NAME' is already running"
    elif [ "$VM_STATUS" = "Stopped" ]; then
        log_info "Starting stopped VM '$VM_NAME'..."
        limactl start "$VM_NAME"
    else
        log_info "Creating and starting VM '$VM_NAME' (first run takes several minutes)..."
        limactl start --name="$VM_NAME" "$LIMA_CONFIG"
    fi
fi

# -- Shell mode ---------------------------------------------------------------

if [ "$SHELL_ONLY" = true ]; then
    log_info "Opening shell in VM '$VM_NAME'..."
    limactl shell "$VM_NAME"
    exit 0
fi

# -- Run tests ----------------------------------------------------------------

echo ""
echo -e "${CYAN}=== OpenClawDefender Lima VM Test Suite ===${NC}"
echo ""

log_info "Checking VM environment..."
run_test "Rust toolchain" lima_exec bash -c "source ~/.cargo/env && rustc --version"
run_test "bpf-linker" lima_exec bash -c "source ~/.cargo/env && which bpf-linker"

log_info "Building eBPF program..."
run_test "cargo xtask build-ebpf" \
    lima_exec bash -c "cd $PROJECT_DIR && source ~/.cargo/env && cargo xtask build-ebpf"

log_info "Building user-space daemon..."
run_test "cargo xtask build" \
    lima_exec bash -c "cd $PROJECT_DIR && source ~/.cargo/env && cargo xtask build"

log_info "Running unit tests..."
run_test "claw-wall-common tests" \
    lima_exec bash -c "cd $PROJECT_DIR && source ~/.cargo/env && cargo test --package claw-wall-common"

log_info "Testing CLI..."
run_test "claw-wall --help" \
    lima_exec bash -c "cd $PROJECT_DIR && ./target/debug/claw-wall --help"

log_info "Testing --install-service (needs sudo)..."
run_test "claw-wall --install-service" \
    lima_exec sudo bash -c "cd $PROJECT_DIR && ./target/debug/claw-wall --install-service"

run_test "systemd unit created" \
    lima_exec test -f /etc/systemd/system/claw-wall.service

log_info "Testing --configure (piped input)..."
run_test "claw-wall --configure" \
    lima_exec bash -c "echo 'test-api-key-12345' | sudo $PROJECT_DIR/target/debug/claw-wall --configure"

run_test "config file created" \
    lima_exec sudo test -f /etc/claw-wall/config.toml

log_info "Checking BPF kernel support..."
run_test "CONFIG_BPF=y" \
    lima_exec bash -c "grep -q 'CONFIG_BPF=y' /boot/config-\$(uname -r) 2>/dev/null || zcat /proc/config.gz 2>/dev/null | grep -q 'CONFIG_BPF=y'"

log_info "Testing eBPF program loading (requires root + BPF)..."
lima_exec sudo bash -c "cd $PROJECT_DIR && timeout 5 ./target/debug/claw-wall run 2>&1 || true"
log_info "eBPF load test completed (check output above)"

# -- Results ------------------------------------------------------------------

echo ""
echo "========================================"
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "========================================"

# -- Cleanup ------------------------------------------------------------------

if [ "$DESTROY_AFTER" = true ]; then
    log_info "Destroying VM '$VM_NAME'..."
    limactl stop "$VM_NAME" 2>/dev/null || true
    limactl delete "$VM_NAME" 2>/dev/null || true
fi

exit "$FAIL"
