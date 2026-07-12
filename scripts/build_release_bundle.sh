#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:-$(git -C "$ROOT_DIR" describe --tags --always --dirty)}
SAFE_VERSION=${VERSION#v}
DIST_DIR="$ROOT_DIR/dist"
PACKAGE_NAME="regentclaw-${SAFE_VERSION}"
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
cp "$ROOT_DIR/README.md" "$STAGE_DIR/README.md"
cp "$ROOT_DIR/LICENSE" "$STAGE_DIR/LICENSE"
cp "$ROOT_DIR/docs/installation.md" "$STAGE_DIR/docs/installation.md"
cp "$ROOT_DIR/docs/native-installers.md" "$STAGE_DIR/docs/native-installers.md"
cp "$ROOT_DIR/docs/production-deployment.md" "$STAGE_DIR/docs/production-deployment.md"
printf '%s\n' "$VERSION" > "$STAGE_DIR/VERSION"
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
