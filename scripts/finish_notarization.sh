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
# --verbose prints each transfer/poll step, which is the only way to tell a slow
# upload apart from a submission stuck on Apple's side. 0.8.0 hung until the same
# artifact was resubmitted, so a timed first attempt gets one automatic retry.
#
# notarytool has also crashed (Bus error) partway through its S3 multipart
# upload while the submission still registered and completed server-side.
# Blindly resubmitting there wastes a full upload, so the submission id is
# captured and polled before deciding anything.
SUBMIT_LOG="$(mktemp -t enkstein-notary)"

submit() {
  xcrun notarytool submit "$PKG" \
    --keychain-profile "$PROFILE" \
    --timeout "${NOTARY_TIMEOUT:-30m}" \
    --verbose \
    --wait 2>&1 | tee "$SUBMIT_LOG"
  return "${PIPESTATUS[0]}"
}

latest_submission_id() {
  sed -n 's/^ *id: \([0-9a-f-]\{36\}\).*/\1/p' "$SUBMIT_LOG" | tail -1
}

if ! submit; then
  ID="$(latest_submission_id)"
  if [[ -n "$ID" ]]; then
    echo
    echo "Submission $ID already reached Apple; waiting on it instead of re-uploading…"
    if xcrun notarytool wait "$ID" --keychain-profile "$PROFILE" --timeout "${NOTARY_TIMEOUT:-30m}"; then
      ID=""  # accepted
    fi
  fi
  if [[ -n "$ID" || -z "$(latest_submission_id)" ]]; then
  echo
  echo "First submission did not reach a terminal status. Resubmitting the same package…"
  submit
  fi
fi

xcrun stapler staple "$PKG"
# Gatekeeper is the only check that matters; a stapled ticket still has to pass.
spctl -a -vv -t install "$PKG"
shasum -a 256 "$PKG"
echo "Notarized and stapled: $PKG"
