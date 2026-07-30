#!/usr/bin/env bash
set -euo pipefail

export PATH="/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

APP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE_RUNTIME="$APP_ROOT/Resources/runtime"
USER_ROOT="$HOME/Library/Application Support/Marcellus"
RUNTIME_DIR="$USER_ROOT/runtime"
LOG_DIR="$HOME/Library/Logs/Marcellus"
LOG_FILE="$LOG_DIR/launcher.log"
LOCK_DIR="$USER_ROOT/.launch-lock"
TEMP_DIR="$USER_ROOT/tmp"
BRIDGE_PORT=47831
BRIDGE_SECRET_FILE="$USER_ROOT/brain-bridge.secret"
BRIDGE_PID_FILE="$USER_ROOT/brain-bridge.pid"
BRIDGE_VERSION_FILE="$USER_ROOT/brain-bridge.version"
BRIDGE_PLIST="$HOME/Library/LaunchAgents/com.marcellus.brain-bridge.plist"

mkdir -p "$USER_ROOT" "$LOG_DIR" "$TEMP_DIR"
export TMPDIR="$TEMP_DIR"

notify_status() {
  printf '%s\n' "$1"
}

show_error() {
  local message="$1"
  printf 'ERROR: %s\n' "$message" >&2
  if [ "${MARCELLUS_EMBEDDED:-0}" = "1" ]; then
    return
  fi
  /usr/bin/osascript -e "display dialog \"Enkstein could not start. ${message}\" buttons {\"OK\"} default button \"OK\" with icon stop" >/dev/null 2>&1 || true
}

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  notify_status "Enkstein is already starting. Waiting for the secure runtime..."
  if [ "${MARCELLUS_EMBEDDED:-0}" != "1" ]; then
    /usr/bin/open "http://127.0.0.1:3000/marcellus"
  fi
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

if [ ! -f "$SOURCE_RUNTIME/VERSION" ]; then
  show_error "The application runtime is missing. Reinstall Enkstein."
  exit 1
fi

notify_status "Preparing the Enkstein runtime..."
source_version=$(tr -d '\r\n' < "$SOURCE_RUNTIME/VERSION")
runtime_version=${source_version#v}
installed_version=""
if [ -f "$RUNTIME_DIR/VERSION" ]; then
  installed_version=$(tr -d '\r\n' < "$RUNTIME_DIR/VERSION")
fi
source_digest=""
installed_digest=""
if [ -f "$SOURCE_RUNTIME/RUNTIME_DIGEST" ]; then
  source_digest=$(tr -d '\r\n' < "$SOURCE_RUNTIME/RUNTIME_DIGEST")
fi
if [ -f "$RUNTIME_DIR/RUNTIME_DIGEST" ]; then
  installed_digest=$(tr -d '\r\n' < "$RUNTIME_DIR/RUNTIME_DIGEST")
fi

if [ "$source_version" != "$installed_version" ] || \
   { [ -n "$source_digest" ] && [ "$source_digest" != "$installed_digest" ]; }; then
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

# Preserve credentials and operator settings across upgrades, while package
# identity remains authoritative for the displayed runtime version.
if [ -f "$RUNTIME_DIR/.env" ]; then
  if grep -q '^APP_VERSION=' "$RUNTIME_DIR/.env"; then
    sed -i '' "s/^APP_VERSION=.*/APP_VERSION=${runtime_version}/" "$RUNTIME_DIR/.env"
  else
    printf '\nAPP_VERSION=%s\n' "$runtime_version" >> "$RUNTIME_DIR/.env"
  fi
fi

ensure_env_value() {
  local key="$1"
  local value="$2"
  if grep -q "^${key}=" "$RUNTIME_DIR/.env"; then
    sed -i '' "s|^${key}=.*|${key}=${value}|" "$RUNTIME_DIR/.env"
  else
    printf '\n%s=%s\n' "$key" "$value" >> "$RUNTIME_DIR/.env"
  fi
}

find_free_port() {
  # Keep the familiar port when it is genuinely free so documented URLs keep
  # working; step aside only when something already holds it.
  local preferred="$1"
  local candidate="$preferred"
  local limit=$((preferred + 20))
  while [ "$candidate" -le "$limit" ]; do
    if ! /usr/bin/nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done
  printf '%s' "$preferred"
}

# Returns the PID currently bound to BRIDGE_PORT in LISTEN state, or nothing.
bridge_port_owner() {
  /usr/sbin/lsof -nP -iTCP:"$BRIDGE_PORT" -sTCP:LISTEN -t 2>/dev/null | head -1
}

start_brain_bridge() {
  local bridge="$APP_ROOT/Resources/EnksteinBrainBridge"
  [ -x "$bridge" ] || return 0
  if [ ! -s "$BRIDGE_SECRET_FILE" ]; then
    /usr/bin/openssl rand -hex 32 > "$BRIDGE_SECRET_FILE"
    chmod 600 "$BRIDGE_SECRET_FILE"
  fi
  local secret
  secret=$(tr -d '\r\n' < "$BRIDGE_SECRET_FILE")
  ensure_env_value BRAIN_BRIDGE_URL "http://host.docker.internal:${BRIDGE_PORT}"
  ensure_env_value BRAIN_BRIDGE_SECRET "$secret"
  ensure_env_value BRAIN_BRIDGE_TIMEOUT_SECONDS "180"
  chmod 600 "$RUNTIME_DIR/.env"

  if [ -f "$BRIDGE_VERSION_FILE" ] && [ "$(cat "$BRIDGE_VERSION_FILE")" = "$source_version" ] && \
     /bin/launchctl print "gui/$(id -u)/com.marcellus.brain-bridge" >/dev/null 2>&1 && \
     [ -n "$(bridge_port_owner)" ]; then
     # Version already matches and something is genuinely listening on the
     # bridge port -- nothing to do. (Previously this only checked that the
     # launchd job was registered, not that a process was actually bound to
     # the port; a stuck/orphaned prior instance holding the port while a
     # fresh launchd-managed instance repeatedly failed to bind behind it
     # was invisible to that check, so a stale bridge from a much earlier
     # launch could silently keep answering every request indefinitely.)
    return 0
  fi

  mkdir -p "$(dirname "$BRIDGE_PLIST")"
  cat > "$BRIDGE_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.marcellus.brain-bridge</string>
  <key>ProgramArguments</key>
  <array>
    <string>${bridge}</string>
    <string>--port</string><string>${BRIDGE_PORT}</string>
    <string>--secret-file</string><string>${BRIDGE_SECRET_FILE}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>${LOG_DIR}/brain-bridge.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/brain-bridge.log</string>
</dict>
</plist>
PLIST
  chmod 600 "$BRIDGE_PLIST"
  /bin/launchctl bootout "gui/$(id -u)/com.marcellus.brain-bridge" >/dev/null 2>&1 || true

  # bootout asks launchd to stop the job, but if the running binary predates
  # this launcher's process-group/signal wiring it can end up detached from
  # launchd (PPID 1) and simply not exit -- bootout then reports success
  # while the old process keeps holding the port. Wait briefly for the port
  # to actually free up, then fall back to killing whatever still owns it
  # directly, so a fresh bootstrap always gets a clean bind instead of
  # starting a new instance that immediately loses to a zombie predecessor.
  for _ in $(seq 1 10); do
    [ -z "$(bridge_port_owner)" ] && break
    sleep 0.3
  done
  stale_owner=$(bridge_port_owner)
  if [ -n "$stale_owner" ]; then
    kill -TERM "$stale_owner" >/dev/null 2>&1 || true
    sleep 1
    stale_owner=$(bridge_port_owner)
    [ -n "$stale_owner" ] && kill -KILL "$stale_owner" >/dev/null 2>&1 || true
    sleep 0.5
  fi

  if ! /bin/launchctl bootstrap "gui/$(id -u)" "$BRIDGE_PLIST"; then
    nohup "$bridge" --port "$BRIDGE_PORT" --secret-file "$BRIDGE_SECRET_FILE" \
      >>"$LOG_DIR/brain-bridge.log" 2>&1 </dev/null &
    printf '%s\n' "$!" > "$BRIDGE_PID_FILE"
  fi

  # Confirm the new instance actually bound the port before recording this
  # version as successfully deployed; otherwise the next launch retries
  # instead of silently treating a failed restart as done.
  for _ in $(seq 1 20); do
    [ -n "$(bridge_port_owner)" ] && break
    sleep 0.3
  done
  printf '%s\n' "$source_version" > "$BRIDGE_VERSION_FILE"
}

if ! command -v docker >/dev/null 2>&1; then
  show_error "Docker Desktop is required. Install Docker Desktop, then launch Enkstein again."
  /usr/bin/open "https://www.docker.com/products/docker-desktop/" || true
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  notify_status "Starting Docker Desktop..."
  /usr/bin/open -a Docker >/dev/null 2>&1 || true
  /usr/bin/osascript -e 'display notification "Waiting for Docker Desktop to start" with title "Enkstein"' >/dev/null 2>&1 || true
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
  echo "[$(date -u +%FT%TZ)] Starting Enkstein $source_version"
  cd "$RUNTIME_DIR"
  notify_status "Starting governed services. The first launch may take a few minutes..."
  ./install.sh --no-start
  # Choose ports before starting. Binding 3000 or 8000 unconditionally fails
  # when anything else already holds them, and Compose reports only that the
  # container could not start.
  ensure_env_value FRONTEND_PORT "$(find_free_port 3000)"
  ensure_env_value BACKEND_PORT "$(find_free_port 8000)"
  start_brain_bridge
  ./install.sh
} >>"$LOG_FILE" 2>&1 || {
  show_error "See $LOG_FILE for details."
  exit 1
}

read_env_value() {
  local key="$1"
  local fallback="$2"
  local value
  value=$(sed -n "s/^${key}=//p" "$RUNTIME_DIR/.env" | tail -1)
  printf '%s' "${value:-$fallback}"
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local attempts="${3:-180}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if /usr/bin/curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  show_error "$name did not become ready. See $LOG_FILE for details."
  return 1
}

frontend_port=$(read_env_value FRONTEND_PORT 3000)
backend_port=$(read_env_value BACKEND_PORT 8000)
ui_url="http://127.0.0.1:${frontend_port}/marcellus"
printf '%s\n' "$ui_url" > "$USER_ROOT/ui-url"

notify_status "Waiting for the Cortex and Trust Fabric..."
wait_for_url "The backend" "http://127.0.0.1:${backend_port}/health" 300
notify_status "Waiting for the Enkstein desktop..."
wait_for_url "The desktop UI" "http://127.0.0.1:${frontend_port}/" 180
notify_status "Enkstein is ready."

if [ "${MARCELLUS_EMBEDDED:-0}" != "1" ]; then
  /usr/bin/open "$ui_url"
fi
