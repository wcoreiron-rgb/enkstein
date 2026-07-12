#!/usr/bin/env bash
set -euo pipefail
export COPYFILE_DISABLE=1

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS is required to build the RegentClaw .pkg." >&2
  exit 1
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:-0.7.0}
VERSION=${VERSION#v}
DIST_DIR="$ROOT_DIR/dist"
WORK_DIR="$DIST_DIR/macos-$VERSION"
APP_DIR="$WORK_DIR/pkgroot/Applications/RegentClaw.app"
CONTENTS_DIR="$APP_DIR/Contents"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
MACOS_DIR="$CONTENTS_DIR/MacOS"
OUTPUT_PKG="$DIST_DIR/RegentClaw-$VERSION-macos.pkg"

for command in pkgbuild productbuild codesign iconutil sips; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Missing required macOS build tool: $command" >&2
    exit 1
  }
done

"$ROOT_DIR/scripts/build_release_bundle.sh" "v$VERSION"

rm -rf "$WORK_DIR" "$OUTPUT_PKG"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
cp "$ROOT_DIR/packaging/macos/launcher.sh" "$MACOS_DIR/RegentClaw"
chmod +x "$MACOS_DIR/RegentClaw"
sed "s/__VERSION__/$VERSION/g" "$ROOT_DIR/packaging/macos/Info.plist.in" > "$CONTENTS_DIR/Info.plist"
/usr/bin/ditto --norsrc --noextattr --noqtn "$DIST_DIR/regentclaw-$VERSION" "$RESOURCES_DIR/runtime"

ICONSET="$WORK_DIR/RegentClaw.iconset"
mkdir -p "$ICONSET"
ICON_SOURCE="$ROOT_DIR/frontend/public/logo.png"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  retina=$((size * 2))
  sips -z "$retina" "$retina" "$ICON_SOURCE" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$RESOURCES_DIR/RegentClaw.icns"
xattr -cr "$APP_DIR"

if [ -n "${APPLE_APPLICATION_SIGNING_IDENTITY:-}" ]; then
  codesign --force --deep --options runtime --timestamp \
    --sign "$APPLE_APPLICATION_SIGNING_IDENTITY" "$APP_DIR"
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
else
  codesign --force --deep --sign - "$APP_DIR"
  echo "Built with ad-hoc app signing for local validation."
fi

COMPONENT_PKG="$WORK_DIR/RegentClaw-component.pkg"
pkgbuild --root "$WORK_DIR/pkgroot" \
  --identifier com.regentclaw.desktop \
  --version "$VERSION" \
  --install-location / \
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

pkgutil --payload-files "$OUTPUT_PKG" | grep -q 'Applications/RegentClaw.app'
echo "Built: $OUTPUT_PKG"
