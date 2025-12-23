#!/bin/bash
#
# cleanup.sh - Glarus PoC Cleanup Script
#
# Restores the system to its pre-exploit state:
# - Handles incomplete swaps from rename-based attack
# - Removes symlinks if present (from old symlink-based method)
# - Restores Data directory from backup
# - Removes Fake directory and hardlinks
#
# NOTE: This does NOT restore ownership of any files that were
# successfully exploited - that requires root access.
#
# Copyright (c) 2025 Golden Helm Securities
#

# Use the same fixed bundle ID
BUNDLE_ID="${GLARUS_BUNDLE_ID:-com.glarus.poc}"
CONTAINER_BASE="$HOME/Library/Containers/$BUNDLE_ID"

echo "═══════════════════════════════════════════════════════════════"
echo "  Glarus PoC - Cleanup"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "Bundle ID: $BUNDLE_ID"
echo "Container: $CONTAINER_BASE"
echo

DATA_DIR="$CONTAINER_BASE/Data"
DATA_BACKUP="$CONTAINER_BASE/Data_backup"
FAKE_DIR="$CONTAINER_BASE/Fake"

#───────────────────────────────────────────────────────────────────────────────
# Remove Data symlink (if present from incomplete exploit)
#───────────────────────────────────────────────────────────────────────────────

if [ -L "$DATA_DIR" ]; then
    echo "[*] Removing Data symlink..."
    rm -f "$DATA_DIR"
    echo "    ✓ Symlink removed"
fi

#───────────────────────────────────────────────────────────────────────────────
# Restore Data from backup if Data is missing
#───────────────────────────────────────────────────────────────────────────────

if [ ! -e "$DATA_DIR" ] && [ -d "$DATA_BACKUP" ]; then
    echo "[*] Restoring Data from backup..."
    mv "$DATA_BACKUP" "$DATA_DIR"
    echo "    ✓ Data restored"
fi

#───────────────────────────────────────────────────────────────────────────────
# Remove leftover Data_backup
#───────────────────────────────────────────────────────────────────────────────

if [ -d "$DATA_BACKUP" ]; then
    echo "[*] Removing leftover Data_backup..."
    rm -rf "$DATA_BACKUP"
    echo "    ✓ Data_backup removed"
fi

#───────────────────────────────────────────────────────────────────────────────
# Create Data directory if it doesn't exist
#───────────────────────────────────────────────────────────────────────────────

if [ ! -d "$DATA_DIR" ]; then
    echo "[*] Creating fresh Data directory..."
    mkdir -p "$DATA_DIR"
    echo "    ✓ Data directory created"
fi

#───────────────────────────────────────────────────────────────────────────────
# Remove Fake directory
#───────────────────────────────────────────────────────────────────────────────

if [ -e "$FAKE_DIR" ]; then
    echo "[*] Removing Fake directory..."
    # Note: Even if Fake/tmp is a hardlink to a root-owned file,
    # we can remove it because we own the Fake directory
    rm -rf "$FAKE_DIR"
    echo "    ✓ Fake directory removed"
fi

#───────────────────────────────────────────────────────────────────────────────
# Clean up tmp directory
#───────────────────────────────────────────────────────────────────────────────

if [ -d "$DATA_DIR/tmp" ]; then
    echo "[*] Removing leftover tmp directory..."
    rmdir "$DATA_DIR/tmp" 2>/dev/null || rm -rf "$DATA_DIR/tmp"
    echo "    ✓ tmp directory removed"
fi

#───────────────────────────────────────────────────────────────────────────────
# Summary
#───────────────────────────────────────────────────────────────────────────────

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Cleanup Complete"
echo "═══════════════════════════════════════════════════════════════"
echo

if [ -d "$CONTAINER_BASE" ]; then
    echo "Container state:"
    ls -la "$CONTAINER_BASE/" 2>/dev/null || echo "  (empty or removed)"
fi

echo
echo "NOTE: If files were successfully exploited, their ownership has"
echo "      been permanently changed and requires root access to restore."
echo
