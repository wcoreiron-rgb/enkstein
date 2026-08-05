#!/usr/bin/env bash
set -euo pipefail
export COPYFILE_DISABLE=1

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS is required to build the Enkstein .pkg." >&2
  exit 1
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:-0.7.10}
VERSION=${VERSION#v}
DIST_DIR="$ROOT_DIR/dist"
WORK_DIR="$DIST_DIR/macos-$VERSION"
APP_DIR="$WORK_DIR/pkgroot/Applications/Enkstein.app"
CONTENTS_DIR="$APP_DIR/Contents"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
MACOS_DIR="$CONTENTS_DIR/MacOS"
OUTPUT_PKG="$DIST_DIR/Enkstein-$VERSION-macos.pkg"

mkdir -p "$DIST_DIR"
touch "$DIST_DIR/.metadata_never_index"

for command in pkgbuild productbuild codesign iconutil sips swiftc lipo; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required macOS build tool: $command" >&2
    exit 1
  }
done

"$ROOT_DIR/scripts/build_release_bundle.sh" "v$VERSION"

# Staged .app bundles are discoverable by Spotlight and can appear as duplicate
# applications in Launchpad. They are disposable build products, not releases.
while IFS= read -r stale_work_dir; do
  if ! rm -rf "$stale_work_dir" 2>/dev/null; then
    echo "Warning: could not remove root-owned staging directory: $stale_work_dir" >&2
  fi
done < <(find "$DIST_DIR" -maxdepth 1 -type d -name 'macos-*' -print)
find "$DIST_DIR" -maxdepth 1 -type f \( -name 'Marcellus-*-macos.pkg' -o -name 'Enkstein-*-macos.pkg' \) ! -name "$(basename "$OUTPUT_PKG")" -delete
rm -rf "$WORK_DIR" "$OUTPUT_PKG"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
cp "$ROOT_DIR/packaging/macos/launcher.sh" "$RESOURCES_DIR/launcher.sh"
chmod +x "$RESOURCES_DIR/launcher.sh"
cp "$ROOT_DIR/packaging/macos/docker-prerequisite.sh" "$RESOURCES_DIR/docker-prerequisite.sh"
chmod +x "$RESOURCES_DIR/docker-prerequisite.sh"
cp -R "$ROOT_DIR/browser-extension" "$RESOURCES_DIR/browser-extension"
sed "s/__VERSION__/$VERSION/g" "$ROOT_DIR/packaging/macos/Info.plist.in" > "$CONTENTS_DIR/Info.plist"
/usr/bin/ditto --norsrc --noextattr --noqtn "$DIST_DIR/enkstein-$VERSION" "$RESOURCES_DIR/runtime"

SWIFT_SOURCE="$ROOT_DIR/packaging/macos/MarcellusApp.swift"
ARM_BINARY="$WORK_DIR/Enkstein-arm64"
INTEL_BINARY="$WORK_DIR/Enkstein-x86_64"
xcrun swiftc "$SWIFT_SOURCE" -O -target arm64-apple-macos12.0 \
  -framework Cocoa -framework WebKit -framework CoreVideo -o "$ARM_BINARY"
xcrun swiftc "$SWIFT_SOURCE" -O -target x86_64-apple-macos12.0 \
  -framework Cocoa -framework WebKit -framework CoreVideo -o "$INTEL_BINARY"
lipo -create "$ARM_BINARY" "$INTEL_BINARY" -output "$MACOS_DIR/Enkstein"
chmod +x "$MACOS_DIR/Enkstein"

BRIDGE_SOURCE="$ROOT_DIR/packaging/macos/MarcellusBrainBridge.swift"
BRIDGE_ARM_BINARY="$WORK_DIR/EnksteinBrainBridge-arm64"
BRIDGE_INTEL_BINARY="$WORK_DIR/EnksteinBrainBridge-x86_64"
xcrun swiftc "$BRIDGE_SOURCE" -O -target arm64-apple-macos12.0 \
  -framework Network -framework AppKit -framework ApplicationServices -o "$BRIDGE_ARM_BINARY"
xcrun swiftc "$BRIDGE_SOURCE" -O -target x86_64-apple-macos12.0 \
  -framework Network -framework AppKit -framework ApplicationServices -o "$BRIDGE_INTEL_BINARY"
lipo -create "$BRIDGE_ARM_BINARY" "$BRIDGE_INTEL_BINARY" -output "$RESOURCES_DIR/EnksteinBrainBridge"
chmod +x "$RESOURCES_DIR/EnksteinBrainBridge"

ICONSET="$WORK_DIR/Enkstein.iconset"
mkdir -p "$ICONSET"
ICON_SOURCE="$ROOT_DIR/frontend/public/enkstein-icon.png"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  retina=$((size * 2))
  sips -z "$retina" "$retina" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$RESOURCES_DIR/Enkstein.icns"
xattr -cr "$APP_DIR"

if [ -n "${APPLE_APPLICATION_SIGNING_IDENTITY:-}" ]; then
  # Executables stored directly under Resources are not reliably discovered by
  # --deep. Sign the host bridge explicitly before sealing the app bundle.
  codesign --force --options runtime --timestamp \
    --sign "$APPLE_APPLICATION_SIGNING_IDENTITY" "$RESOURCES_DIR/EnksteinBrainBridge"
  codesign --force --deep --options runtime --timestamp \
    --sign "$APPLE_APPLICATION_SIGNING_IDENTITY" "$APP_DIR"
  codesign --verify --strict --verbose=2 "$RESOURCES_DIR/EnksteinBrainBridge"
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
else
  codesign --force --sign - "$RESOURCES_DIR/EnksteinBrainBridge"
  codesign --force --deep --sign - "$APP_DIR"
  echo "Built with ad-hoc app signing for local validation."
fi

COMPONENT_PKG="$WORK_DIR/Enkstein-component.pkg"
pkgbuild --root "$WORK_DIR/pkgroot" \
  --identifier com.marcellus.desktop \
  --version "$VERSION" \
  --install-location / \
  --component-plist "$ROOT_DIR/packaging/macos/component.plist" \
  --scripts "$ROOT_DIR/packaging/macos/pkg-scripts" \
  "$COMPONENT_PKG"

if [ -n "${APPLE_INSTALLER_SIGNING_IDENTITY:-}" ]; then
  productbuild --package "$COMPONENT_PKG" \
    --sign "$APPLE_INSTALLER_SIGNING_IDENTITY" "$OUTPUT_PKG"
  pkgutil --check-signature "$OUTPUT_PKG"
else
  productbuild --package "$COMPONENT_PKG" "$OUTPUT_PKG"
  echo "Built an unsigned installer for local validation."
fi

pkgutil --payload-files "$OUTPUT_PKG" | grep -F 'Applications/Enkstein.app' >/dev/null
rm -rf "$WORK_DIR"
echo "Built: $OUTPUT_PKG"
