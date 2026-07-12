#!/usr/bin/env bash
set -euo pipefail

export PATH="/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

APP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE_RUNTIME="$APP_ROOT/Resources/runtime"
USER_ROOT="$HOME/Library/Application Support/RegentClaw"
RUNTIME_DIR="$USER_ROOT/runtime"
LOG_DIR="$HOME/Library/Logs/RegentClaw"
LOG_FILE="$LOG_DIR/launcher.log"
LOCK_DIR="$USER_ROOT/.launch-lock"

mkdir -p "$USER_ROOT" "$LOG_DIR"

show_error() {
  local message="$1"
  /usr/bin/osascript -e "display dialog \"RegentClaw could not start. ${message}\" buttons {\"OK\"} default button \"OK\" with icon stop" >/dev/null 2>&1 || true
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  /usr/bin/open "http://localhost:3000"
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

if [ ! -f "$SOURCE_RUNTIME/VERSION" ]; then
  show_error "The application runtime is missing. Reinstall RegentClaw."
  exit 1
fi

source_version=$(tr -d '\r\n' < "$SOURCE_RUNTIME/VERSION")
installed_version=""
if [ -f "$RUNTIME_DIR/VERSION" ]; then
  installed_version=$(tr -d '\r\n' < "$RUNTIME_DIR/VERSION")
fi

if [ "$source_version" != "$installed_version" ]; then
  temp_runtime="$USER_ROOT/runtime.new"
  saved_env="$USER_ROOT/.env.saved"
  rm -rf "$temp_runtime" "$saved_env"
  if [ -f "$RUNTIME_DIR/.env" ]; then
    cp "$RUNTIME_DIR/.env" "$saved_env"
  fi
  /usr/bin/ditto "$SOURCE_RUNTIME" "$temp_runtime"
  rm -rf "$RUNTIME_DIR"
  mv "$temp_runtime" "$RUNTIME_DIR"
  if [ -f "$saved_env" ]; then
    mv "$saved_env" "$RUNTIME_DIR/.env"
    chmod 600 "$RUNTIME_DIR/.env"
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  show_error "Docker Desktop is required. Install Docker Desktop, then launch RegentClaw again."
  /usr/bin/open "https://www.docker.com/products/docker-desktop/" || true
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  /usr/bin/open -a Docker >/dev/null 2>&1 || true
  /usr/bin/osascript -e 'display notification "Waiting for Docker Desktop to start" with title "RegentClaw"' >/dev/null 2>&1 || true
  for _ in $(seq 1 60); do
    if docker info >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
fi

if ! docker info >/dev/null 2>&1; then
  show_error "Docker Desktop did not become ready within two minutes."
  exit 1
fi

{
  echo "[$(date -u +%FT%TZ)] Starting RegentClaw $source_version"
  cd "$RUNTIME_DIR"
  ./install.sh
} >>"$LOG_FILE" 2>&1 || {
  show_error "See $LOG_FILE for details."
  exit 1
}

/usr/bin/open "http://localhost:3000"
