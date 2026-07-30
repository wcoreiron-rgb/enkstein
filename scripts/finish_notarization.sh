#!/usr/bin/env bash
# Notarize, staple, and verify an already-signed Enkstein macOS package.
#
# The notary credential lives in the login keychain under the profile name
# below. If it is missing, recreate it once with your Apple ID and an
# app-specific password from appleid.apple.com:
#
#   xcrun notarytool store-credentials "enkstein-notary" \
#     --apple-id "you@example.com" --team-id "2575T9PBJH"
#
# Usage: scripts/finish_notarization.sh [version]
set -euo pipefail

VERSION="${1:-}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="enkstein-notary"

if [[ -z "$VERSION" ]]; then
  VERSION="$(sed -n 's/.*"version": "\([0-9.]*\)".*/\1/p' "$REPO/frontend/package.json" | head -1)"
fi

PKG="$REPO/dist/Enkstein-${VERSION}-macos.pkg"
[[ -f "$PKG" ]] || { echo "No package at $PKG — build it first."; exit 1; }

if ! xcrun notarytool history --keychain-profile "$PROFILE" >/dev/null 2>&1; then
  cat >&2 <<MSG
The "$PROFILE" credential is not in the keychain. Create it once:

  xcrun notarytool store-credentials "$PROFILE" \\
    --apple-id "your-apple-id@example.com" --team-id "2575T9PBJH"

then run this script again.
MSG
  exit 1
fi

echo "Submitting $(basename "$PKG")…"
xcrun notarytool submit "$PKG" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$PKG"
# Gatekeeper is the only check that matters; a stapled ticket still has to pass.
spctl -a -vv -t install "$PKG"
shasum -a 256 "$PKG"
echo "Notarized and stapled: $PKG"
