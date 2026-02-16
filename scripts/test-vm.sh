#!/usr/bin/env bash
# ============================================================================
# OpenClawDefender - VM-based Test Runner (Vagrant)
# ============================================================================
#
# Boots an Ubuntu 22.04 VM via Vagrant, builds the project, and runs tests.
# Requires VirtualBox and Vagrant installed.
#
# Prerequisites:
#   brew install --cask virtualbox vagrant
#
# Usage:
#   ./scripts/test-vm.sh              # Full test run (provision + build + test)
#   ./scripts/test-vm.sh --no-up      # Skip vagrant up (VM already running)
#   ./scripts/test-vm.sh --destroy    # Destroy VM after tests
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SKIP_UP=false
DESTROY_AFTER=false

for arg in "$@"; do
    case "$arg" in
        --no-up)    SKIP_UP=true ;;
        --destroy)  DESTROY_AFTER=true ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-up     Skip vagrant up (VM already running)"
            echo "  --destroy   Destroy VM after tests"
            echo "  -h, --help  Show this help"
            exit 0
            ;;
    esac
done

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

PASS=0
FAIL=0

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

cd "$PROJECT_DIR"

# -- Step 1: Boot and provision VM -------------------------------------------

if [ "$SKIP_UP" = false ]; then
    log_info "Starting Vagrant VM..."
    vagrant up
    log_info "Syncing project files..."
    vagrant rsync
fi

# -- Step 2: Build eBPF program ----------------------------------------------

log_info "Building eBPF program in VM..."
run_test "cargo xtask build-ebpf" \
    vagrant ssh -c "cd /home/vagrant/OpenClawDefender && source ~/.cargo/env && cargo xtask build-ebpf"

# -- Step 3: Build user-space daemon -----------------------------------------

log_info "Building user-space daemon in VM..."
run_test "cargo xtask build (full)" \
    vagrant ssh -c "cd /home/vagrant/OpenClawDefender && source ~/.cargo/env && cargo xtask build"

# -- Step 4: Run unit tests ---------------------------------------------------

log_info "Running unit tests..."
run_test "claw-wall-common tests" \
    vagrant ssh -c "cd /home/vagrant/OpenClawDefender && source ~/.cargo/env && cargo test --package claw-wall-common"

# -- Step 5: Check binary and CLI flags ---------------------------------------

log_info "Testing CLI flags..."
run_test "claw-wall --help" \
    vagrant ssh -c "cd /home/vagrant/OpenClawDefender && ./target/debug/claw-wall --help"

# -- Step 6: Test --install-service (needs root) ------------------------------

log_info "Testing --install-service..."
run_test "claw-wall --install-service" \
    vagrant ssh -c "cd /home/vagrant/OpenClawDefender && sudo ./target/debug/claw-wall --install-service"

run_test "systemd unit file created" \
    vagrant ssh -c "test -f /etc/systemd/system/claw-wall.service"

# -- Step 7: Test --configure (piped input) -----------------------------------

log_info "Testing --configure..."
run_test "claw-wall --configure (piped input)" \
    vagrant ssh -c "echo 'test-api-key-12345' | sudo /home/vagrant/OpenClawDefender/target/debug/claw-wall --configure"

run_test "config file created" \
    vagrant ssh -c "sudo test -f /etc/claw-wall/config.toml"

run_test "config file permissions (600)" \
    vagrant ssh -c "sudo stat -c '%a' /etc/claw-wall/config.toml | grep -q '^600$'"

# -- Step 8: Test eBPF loading ------------------------------------------------

log_info "Testing eBPF program loading (may fail in some VM configs)..."
vagrant ssh -c "cd /home/vagrant/OpenClawDefender && sudo timeout 5 ./target/debug/claw-wall run 2>&1 || true"
log_info "eBPF load test completed (check output above)"

# -- Results ------------------------------------------------------------------

echo ""
echo "========================================"
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "========================================"

# -- Cleanup ------------------------------------------------------------------

if [ "$DESTROY_AFTER" = true ]; then
    log_info "Destroying VM..."
    vagrant destroy -f
fi

exit "$FAIL"
