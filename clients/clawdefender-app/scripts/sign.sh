#!/bin/bash
set -euo pipefail

# Usage: ./scripts/sign.sh [ad-hoc|distribution]
# ad-hoc: signs with - (for local dev/testing)
# distribution: signs with Developer ID (requires APPLE_SIGNING_IDENTITY env var)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$SCRIPT_DIR/../src-tauri/target/release/bundle/macos"
APP_NAME="ClawDefender.app"
APP_PATH="$APP_DIR/$APP_NAME"

MODE="${1:-ad-hoc}"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: $APP_PATH not found. Build the app first with 'cargo tauri build'."
    exit 1
fi

case "$MODE" in
    ad-hoc)
        echo "Signing with ad-hoc identity (local dev/testing)..."
        codesign --force --deep --sign - "$APP_PATH"
        echo "Ad-hoc signing complete."
        codesign --verify --verbose "$APP_PATH"
        ;;

    distribution)
        if [ -z "${APPLE_SIGNING_IDENTITY:-}" ]; then
            echo "Error: APPLE_SIGNING_IDENTITY environment variable is not set."
            echo "Set it to your Developer ID Application certificate name, e.g.:"
            echo '  export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"'
            exit 1
        fi

        ENTITLEMENTS="$SCRIPT_DIR/../src-tauri/Entitlements.plist"
        if [ ! -f "$ENTITLEMENTS" ]; then
            echo "Error: Entitlements.plist not found at $ENTITLEMENTS"
            exit 1
        fi

        echo "Signing with Developer ID: $APPLE_SIGNING_IDENTITY"
        codesign --force --deep --options runtime \
            --sign "$APPLE_SIGNING_IDENTITY" \
            --entitlements "$ENTITLEMENTS" \
            "$APP_PATH"

        echo "Verifying signature..."
        codesign --verify --verbose=2 "$APP_PATH"
        spctl --assess --type execute --verbose "$APP_PATH" || true

        # Notarization
        if [ -z "${APPLE_ID:-}" ] || [ -z "${APPLE_TEAM_ID:-}" ]; then
            echo ""
            echo "Skipping notarization: APPLE_ID and/or APPLE_TEAM_ID not set."
            echo "To notarize, set these environment variables:"
            echo "  APPLE_ID        - Your Apple ID email"
            echo "  APPLE_TEAM_ID   - Your Apple Developer Team ID"
            echo "  APPLE_PASSWORD  - App-specific password (or use @keychain:notarytool)"
            exit 0
        fi

        DMG_PATH=$(find "$APP_DIR" -name "*.dmg" | head -1)
        if [ -z "$DMG_PATH" ]; then
            echo "No .dmg found; creating zip for notarization..."
            ZIP_PATH="$APP_DIR/ClawDefender.zip"
            ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
            NOTARIZE_FILE="$ZIP_PATH"
        else
            NOTARIZE_FILE="$DMG_PATH"
        fi

        echo "Submitting for notarization..."
        xcrun notarytool submit "$NOTARIZE_FILE" \
            --apple-id "$APPLE_ID" \
            --team-id "$APPLE_TEAM_ID" \
            --password "${APPLE_PASSWORD:-@keychain:notarytool}" \
            --wait

        echo "Stapling notarization ticket..."
        if [ -n "$DMG_PATH" ]; then
            xcrun stapler staple "$DMG_PATH"
        else
            xcrun stapler staple "$APP_PATH"
        fi

        echo "Distribution signing and notarization complete."
        ;;

    *)
        echo "Usage: $0 [ad-hoc|distribution]"
        echo "  ad-hoc       - Sign with ad-hoc identity (local dev/testing)"
        echo "  distribution - Sign with Developer ID + notarize (requires env vars)"
        exit 1
        ;;
esac
