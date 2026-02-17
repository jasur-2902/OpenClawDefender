#!/bin/bash
set -euo pipefail

# Creates a symlink at /usr/local/bin/clawdefender pointing to the CLI binary
# inside the ClawDefender.app bundle.

APP_PATH="/Applications/ClawDefender.app"
CLI_BINARY="$APP_PATH/Contents/MacOS/clawdefender"
SYMLINK_PATH="/usr/local/bin/clawdefender"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: ClawDefender.app not found at $APP_PATH"
    echo "Please install ClawDefender first."
    exit 1
fi

if [ ! -f "$CLI_BINARY" ]; then
    echo "Error: CLI binary not found at $CLI_BINARY"
    exit 1
fi

if [ -L "$SYMLINK_PATH" ]; then
    echo "Removing existing symlink at $SYMLINK_PATH..."
    sudo rm "$SYMLINK_PATH"
elif [ -f "$SYMLINK_PATH" ]; then
    echo "Warning: $SYMLINK_PATH exists and is not a symlink. Skipping."
    echo "Remove it manually if you want to proceed."
    exit 1
fi

echo "Creating symlink: $SYMLINK_PATH -> $CLI_BINARY"
sudo ln -s "$CLI_BINARY" "$SYMLINK_PATH"
echo "Done. You can now run 'clawdefender' from your terminal."
