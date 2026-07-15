#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:-$(git -C "$ROOT_DIR" describe --tags --always --dirty)}
SAFE_VERSION=${VERSION#v}
DIST_DIR="$ROOT_DIR/dist"
PACKAGE_NAME="marcellus-${SAFE_VERSION}"
STAGE_DIR="$DIST_DIR/$PACKAGE_NAME"

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/docs"

COPYFILE_DISABLE=1 tar -C "$ROOT_DIR" \
  --exclude='.DS_Store' \
  --exclude='backend/.venv' \
  --exclude='backend/.pytest_cache' \
  --exclude='backend/.ruff_cache' \
  --exclude='backend/.secrets' \
  --exclude='backend/.state' \
  --exclude='backend/*.db' \
  --exclude='backend/tests' \
  --exclude='backend/requirements-test.txt' \
  --exclude='*/__pycache__' \
  --exclude='frontend/node_modules' \
  --exclude='frontend/.next' \
  --exclude='frontend/e2e' \
  --exclude='frontend/test-results' \
  --exclude='frontend/playwright-report' \
  -cf - backend frontend | tar -C "$STAGE_DIR" -xf -

cp "$ROOT_DIR/packaging/compose.release.yaml" "$STAGE_DIR/compose.yaml"
cp "$ROOT_DIR/packaging/install.sh" "$STAGE_DIR/install.sh"
cp "$ROOT_DIR/.env.example" "$STAGE_DIR/.env.example"
sed "s/^APP_VERSION=.*/APP_VERSION=$SAFE_VERSION/" "$STAGE_DIR/.env.example" > "$STAGE_DIR/.env.example.tmp"
mv "$STAGE_DIR/.env.example.tmp" "$STAGE_DIR/.env.example"
cp "$ROOT_DIR/README.md" "$STAGE_DIR/README.md"
cp "$ROOT_DIR/LICENSE" "$STAGE_DIR/LICENSE"
cp -R "$ROOT_DIR/browser-extension" "$STAGE_DIR/browser-extension"
cp "$ROOT_DIR/docs/installation.md" "$STAGE_DIR/docs/installation.md"
cp "$ROOT_DIR/docs/native-installers.md" "$STAGE_DIR/docs/native-installers.md"
cp "$ROOT_DIR/docs/brain-bridges.md" "$STAGE_DIR/docs/brain-bridges.md"
cp "$ROOT_DIR/docs/production-deployment.md" "$STAGE_DIR/docs/production-deployment.md"
printf '%s\n' "$VERSION" > "$STAGE_DIR/VERSION"

# A version string alone cannot distinguish two rebuilt installers carrying the
# same version. The launcher compares this content fingerprint before deciding
# whether the user's staged runtime is current.
(
  cd "$STAGE_DIR"
  find backend frontend -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    shasum -a 256 "$file"
  done | shasum -a 256 | awk '{print $1}'
) > "$STAGE_DIR/RUNTIME_DIGEST"
chmod +x "$STAGE_DIR/install.sh"

tar -C "$DIST_DIR" -czf "$DIST_DIR/$PACKAGE_NAME.tar.gz" "$PACKAGE_NAME"
(
  cd "$DIST_DIR"
  rm -f "$PACKAGE_NAME.zip"
  zip -qr "$PACKAGE_NAME.zip" "$PACKAGE_NAME"
)

echo "Built:"
echo "  $DIST_DIR/$PACKAGE_NAME.tar.gz"
echo "  $DIST_DIR/$PACKAGE_NAME.zip"
