#!/usr/bin/env bash
# ============================================================================
# OpenClawDefender - macOS Test Launcher
# ============================================================================
#
# Automatically selects the best available testing method for macOS:
#
#   1. Docker Desktop (recommended, fastest)
#   2. Lima VM (best for full eBPF kernel testing)
#   3. Vagrant + VirtualBox (fallback)
#
# Usage:
#   ./scripts/test-mac.sh                  # Auto-detect and run build tests
#   ./scripts/test-mac.sh --full           # Auto-detect and run full eBPF tests
#   ./scripts/test-mac.sh --docker         # Force Docker
#   ./scripts/test-mac.sh --lima           # Force Lima VM
#   ./scripts/test-mac.sh --vagrant        # Force Vagrant VM
#   ./scripts/test-mac.sh --list           # Show available test backends
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

FORCE_BACKEND=""
EXTRA_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --docker)   FORCE_BACKEND="docker" ;;
        --lima)     FORCE_BACKEND="lima" ;;
        --vagrant)  FORCE_BACKEND="vagrant" ;;
        --list)
            echo "Available test backends:"
            echo ""
            if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
                echo -e "  ${GREEN}[available]${NC} docker   - Docker Desktop (fastest, build + limited eBPF)"
            else
                echo -e "  ${RED}[missing]${NC}   docker   - Install: brew install --cask docker"
            fi
            if command -v limactl >/dev/null 2>&1; then
                echo -e "  ${GREEN}[available]${NC} lima     - Lima VM (full eBPF kernel support)"
            else
                echo -e "  ${RED}[missing]${NC}   lima     - Install: brew install lima"
            fi
            if command -v vagrant >/dev/null 2>&1; then
                echo -e "  ${GREEN}[available]${NC} vagrant  - Vagrant + VirtualBox"
            else
                echo -e "  ${RED}[missing]${NC}   vagrant  - Install: brew install --cask virtualbox vagrant"
            fi
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full       Run full eBPF test suite (not just build validation)"
            echo "  --docker     Force Docker backend"
            echo "  --lima       Force Lima VM backend"
            echo "  --vagrant    Force Vagrant VM backend"
            echo "  --list       Show available test backends"
            echo "  --no-cache   (Docker) Force rebuild"
            echo "  --destroy    (Lima/Vagrant) Destroy VM after tests"
            echo "  -h, --help   Show this help"
            exit 0
            ;;
        *)
            EXTRA_ARGS+=("$arg")
            ;;
    esac
done

detect_backend() {
    # Prefer Docker (fastest iteration), then Lima (best eBPF support), then Vagrant
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        echo "docker"
    elif command -v limactl >/dev/null 2>&1; then
        echo "lima"
    elif command -v vagrant >/dev/null 2>&1; then
        echo "vagrant"
    else
        echo ""
    fi
}

BACKEND="${FORCE_BACKEND:-$(detect_backend)}"

if [ -z "$BACKEND" ]; then
    echo -e "${RED}No test backend available.${NC}"
    echo ""
    echo "Install one of the following:"
    echo "  Docker Desktop:  brew install --cask docker"
    echo "  Lima:            brew install lima"
    echo "  Vagrant:         brew install --cask virtualbox vagrant"
    exit 1
fi

echo -e "${CYAN}Using test backend: ${BACKEND}${NC}"
echo ""

case "$BACKEND" in
    docker)
        exec "$SCRIPT_DIR/test-docker.sh" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
    lima)
        exec "$SCRIPT_DIR/test-lima.sh" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
    vagrant)
        exec "$SCRIPT_DIR/test-vm.sh" "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
        ;;
esac
