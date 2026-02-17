#!/usr/bin/env bash
# Publish the ClawDefender threat feed to GitHub Pages.
#
# Usage:
#   ./publish-feed.sh [--dry-run]
#
# This script:
#   1. Validates all feed JSON files
#   2. Computes SHA-256 hashes and updates manifest.json
#   3. Signs the manifest (if key is available)
#   4. Deploys to the gh-pages branch

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FEED_DIR="${REPO_ROOT}/feed/v1"
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

echo "=== ClawDefender Threat Feed Publisher ==="
echo "Feed directory: ${FEED_DIR}"
echo ""

# Step 1: Validate
echo "--- Step 1: Validating feed ---"
python3 "${SCRIPT_DIR}/validate-feed.py" --feed-dir "${FEED_DIR}"
echo ""

# Step 2: Sign (if key exists)
KEY_FILE="${REPO_ROOT}/feed-private.key"
if [ -f "${KEY_FILE}" ]; then
    echo "--- Step 2: Signing manifest ---"
    python3 "${SCRIPT_DIR}/sign-feed.py" --key "${KEY_FILE}" --feed-dir "${FEED_DIR}"
    echo ""
else
    echo "--- Step 2: Skipping signing (no key file found at ${KEY_FILE}) ---"
    echo "  To sign the feed, run: python3 tools/sign-feed.py --generate-key"
    echo ""
fi

# Step 3: Deploy
if [ "${DRY_RUN}" = true ]; then
    echo "--- Step 3: Dry run - skipping deployment ---"
    echo "  Feed is ready for publishing."
else
    echo "--- Step 3: Deploying to gh-pages ---"

    DEPLOY_DIR=$(mktemp -d)
    trap 'rm -rf "${DEPLOY_DIR}"' EXIT

    cp -r "${FEED_DIR}" "${DEPLOY_DIR}/v1"

    cd "${REPO_ROOT}"

    if git rev-parse --verify gh-pages >/dev/null 2>&1; then
        git checkout gh-pages
    else
        git checkout --orphan gh-pages
        git rm -rf . 2>/dev/null || true
    fi

    rm -rf v1
    cp -r "${DEPLOY_DIR}/v1" .

    git add -A
    git commit -m "Update threat feed $(date -u +%Y-%m-%dT%H:%M:%SZ)" || echo "No changes to commit"
    git push origin gh-pages

    git checkout -

    echo ""
    echo "Feed published to gh-pages branch."
fi

echo ""
echo "=== Done ==="
