#!/usr/bin/env bash
# ============================================================================
# OpenClawDefender - Docker-based Test Runner for macOS
# ============================================================================
#
# This script builds and tests the eBPF firewall inside Docker.
# Docker Desktop for Mac runs a Linux VM under the hood, which provides
# the Linux kernel needed for eBPF compilation and (with --privileged) loading.
#
# Prerequisites:
#   - Docker Desktop for Mac installed and running
#
# Usage:
#   ./scripts/test-docker.sh                # Build validation only (default)
#   ./scripts/test-docker.sh --full         # Full eBPF tests (--privileged)
#   ./scripts/test-docker.sh --shell        # Interactive shell in container
#   ./scripts/test-docker.sh --no-cache     # Force rebuild from scratch
#   ./scripts/test-docker.sh --full --no-cache  # Combine flags
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE_NAME="claw-wall-test"
CONTAINER_NAME="claw-wall-test-run"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BUILD_ARGS=""
RUN_MODE="build"
INTERACTIVE=""

for arg in "$@"; do
    case "$arg" in
        --no-cache) BUILD_ARGS="--no-cache" ;;
        --full)     RUN_MODE="test" ;;
        --shell)    RUN_MODE="shell"; INTERACTIVE="-it" ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full       Run full eBPF tests (requires Docker --privileged)"
            echo "  --shell      Drop into interactive shell inside container"
            echo "  --no-cache   Force Docker rebuild from scratch"
            echo "  -h, --help   Show this help"
            exit 0
            ;;
    esac
done

log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

cd "$PROJECT_DIR"

# -- Preflight checks --------------------------------------------------------

echo -e "${CYAN}"
echo "  ___                    ____ _               ____         __                _           "
echo " / _ \ _ __   ___ _ __ / ___| | __ ___      |  _ \  ___  / _| ___ _ __   __| | ___ _ __ "
echo "| | | | '_ \ / _ \ '_ \ |   | |/ _\` \ \ /\ / / | | |/ _ \ |_ / _ \ '_ \ / _\` |/ _ \ '__|"
echo "| |_| | |_) |  __/ | | | |___| | (_| |\ V  V /| |_| |  __/  _|  __/ | | | (_| |  __/ |   "
echo " \___/| .__/ \___|_| |_\____|_|\__,_| \_/\_/ |____/ \___|_|  \___|_| |_|\__,_|\___|_|   "
echo "      |_|                                                                                 "
echo -e "${NC}"
echo -e "${CYAN}Docker Test Runner for macOS${NC}"
echo ""

# Check Docker is available
if ! command -v docker >/dev/null 2>&1; then
    log_fail "Docker is not installed or not in PATH"
    echo ""
    echo "Install Docker Desktop for Mac:"
    echo "  https://www.docker.com/products/docker-desktop/"
    echo ""
    echo "Or install via Homebrew:"
    echo "  brew install --cask docker"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    log_fail "Docker daemon is not running"
    echo "Start Docker Desktop and try again."
    exit 1
fi

log_pass "Docker is running"

# -- Build the test image ----------------------------------------------------

log_info "Building test image: ${IMAGE_NAME} (this may take a few minutes on first run)"
echo ""

if ! docker build -f Dockerfile.test -t "$IMAGE_NAME" $BUILD_ARGS .; then
    log_fail "Docker build failed"
    exit 1
fi

echo ""
log_pass "Docker image built successfully"

# -- Remove any existing test container ---------------------------------------

docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# -- Run tests ----------------------------------------------------------------

PRIVILEGED_FLAG=""
if [ "$RUN_MODE" = "test" ] || [ "$RUN_MODE" = "shell" ]; then
    PRIVILEGED_FLAG="--privileged"
fi

log_info "Running mode: ${RUN_MODE}"

if docker run --rm $INTERACTIVE $PRIVILEGED_FLAG \
    --name "$CONTAINER_NAME" \
    "$IMAGE_NAME" \
    "$RUN_MODE"; then
    if [ "$RUN_MODE" != "shell" ]; then
        echo ""
        log_pass "Docker test run completed successfully"
    fi
    exit 0
else
    echo ""
    log_fail "Docker test run failed"
    exit 1
fi
