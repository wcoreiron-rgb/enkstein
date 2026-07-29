#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE_FILE="$ROOT_DIR/compose.yaml"
ENV_FILE="$ROOT_DIR/.env"

if [ ! -f "$COMPOSE_FILE" ] && [ -f "$ROOT_DIR/compose.release.yaml" ]; then
  COMPOSE_FILE="$ROOT_DIR/compose.release.yaml"
fi

usage() {
  echo "Usage: ./install.sh [--check|--no-start]"
  echo "  --check     Validate prerequisites and package configuration only"
  echo "  --no-start  Create a secure .env file without starting containers"
}

mode="start"
case "${1:-}" in
  --check) mode="check" ;;
  --no-start) mode="no-start" ;;
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) usage; exit 2 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Desktop or Docker Engine first." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required (the 'docker compose' command)." >&2
  exit 1
fi
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "Missing package file: $COMPOSE_FILE" >&2
  exit 1
fi

if [ "$mode" = "check" ]; then
  check_env="$ENV_FILE"
  if [ ! -f "$check_env" ]; then
    check_env="$ROOT_DIR/.env.example"
  fi
  if [ ! -f "$check_env" ] && [ -f "$ROOT_DIR/../.env.example" ]; then
    check_env="$ROOT_DIR/../.env.example"
  fi
  docker compose --env-file "$check_env" -f "$COMPOSE_FILE" config --quiet
  echo "Enkstein package prerequisites are available."
  exit 0
fi

generate_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import secrets; print(secrets.token_hex($1))"
  else
    echo "OpenSSL or Python 3 is required to generate secure installation secrets." >&2
    exit 1
  fi
}

replace_env() {
  key="$1"
  value="$2"
  sed -i.bak "s|^${key}=.*$|${key}=${value}|" "$ENV_FILE"
  rm -f "$ENV_FILE.bak"
}

append_env_if_missing() {
  key="$1"
  value="$2"
  if ! grep -q "^${key}=" "$ENV_FILE"; then
    printf '\n%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT_DIR/.env.example" "$ENV_FILE"
  replace_env SECRET_KEY "$(generate_hex 32)"
  replace_env POSTGRES_PASSWORD "$(generate_hex 24)"
  replace_env REDIS_PASSWORD "$(generate_hex 24)"
  replace_env ADMIN_PASSWORD "$(generate_hex 24)"
  replace_env DEBUG "false"
  chmod 600 "$ENV_FILE"
  echo "Created .env with unique installation secrets."
else
  echo "Using existing .env; no secrets were overwritten."
fi

# Migrate existing desktop installations without changing established secrets.
append_env_if_missing ADMIN_USERNAME "admin"
append_env_if_missing ADMIN_PASSWORD "$(generate_hex 24)"

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" config --quiet

if [ "$mode" = "no-start" ]; then
  echo "Package configured. Run ./install.sh when ready to start Enkstein."
  exit 0
fi

# Bound the pull. A pull for an image that does not exist yet, or a registry
# that accepts the connection then stalls, otherwise hangs indefinitely and the
# launcher waits forever with no error. Prefer a timed attempt and a local build
# over a launch that never finishes.
run_bounded() {
  timeout_seconds="$1"
  shift
  "$@" &
  bounded_pid=$!
  elapsed=0
  while [ "$elapsed" -lt "$timeout_seconds" ]; do
    if ! kill -0 "$bounded_pid" 2>/dev/null; then
      wait "$bounded_pid"
      return $?
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  kill -TERM "$bounded_pid" 2>/dev/null || true
  sleep 2
  kill -KILL "$bounded_pid" 2>/dev/null || true
  wait "$bounded_pid" 2>/dev/null || true
  return 124
}

# Prefer published images so a first launch is a download rather than a local
# compile. Building the backend image installs a large toolchain and Prowler,
# which is what made first launch take minutes. If the pull cannot complete —
# offline, registry unreachable, or a local/dev checkout with no published tag —
# fall back to building so the install still succeeds.
if [ "${ENKSTEIN_FORCE_BUILD:-false}" = "true" ]; then
  echo "ENKSTEIN_FORCE_BUILD=true — building images locally."
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build
elif run_bounded "${ENKSTEIN_PULL_TIMEOUT:-600}" docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull --quiet backend frontend; then
  echo "Using published Enkstein images."
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --no-build
else
  echo "Published images were unavailable — building locally instead. This takes a few minutes."
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build
fi
echo "Enkstein is starting."
echo "UI:       http://localhost:${FRONTEND_PORT:-3000}"
echo "API docs: http://localhost:${BACKEND_PORT:-8000}/docs"
echo "Status:   docker compose --env-file .env -f compose.yaml ps"
