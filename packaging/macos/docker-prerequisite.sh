#!/usr/bin/env bash
# Docker Desktop gate for the Enkstein macOS launcher.
#
# The helper is deliberately side-effect-light and emits machine-readable state
# lines so the native splash can show an actionable prerequisite screen. Tests
# can override the command/app/open variables without touching a real Docker
# installation.

DOCKER_COMMAND="${ENKSTEIN_DOCKER_COMMAND:-docker}"
DOCKER_APP="${ENKSTEIN_DOCKER_APP:-/Applications/Docker.app}"
DOCKER_OPEN="${ENKSTEIN_DOCKER_OPEN:-/usr/bin/open}"
DOCKER_INSTALL_URL="https://www.docker.com/products/docker-desktop/"

docker_state() {
  local state="$1"
  local detail="$2"
  printf 'ENKSTEIN_DOCKER_STATE=%s|%s\n' "$state" "$detail"
}

docker_installed() {
  command -v "$DOCKER_COMMAND" >/dev/null 2>&1 || [ -d "$DOCKER_APP" ]
}

docker_healthy() {
  "$DOCKER_COMMAND" info >/dev/null 2>&1
}

docker_desktop_running() {
  /usr/bin/pgrep -f "Docker Desktop" >/dev/null 2>&1
}

open_docker() {
  if [ -d "$DOCKER_APP" ]; then
    "$DOCKER_OPEN" -a Docker >/dev/null 2>&1 || true
  fi
}

open_docker_install() {
  "$DOCKER_OPEN" "$DOCKER_INSTALL_URL" >/dev/null 2>&1 || true
}

wait_for_docker() {
  local attempts="${1:-60}"
  local interval="${2:-2}"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    docker_state "starting" "Waiting for Docker Desktop engine (${attempt}/${attempts})..."
    if docker_healthy; then return 0; fi
    sleep "$interval"
  done
  return 1
}

ensure_docker() {
  if ! command -v "$DOCKER_COMMAND" >/dev/null 2>&1 && [ ! -d "$DOCKER_APP" ]; then
    docker_state "missing" "Docker Desktop is required before Enkstein can start."
    open_docker_install
    # ENKSTEIN_DOCKER_INSTALL_ATTEMPTS=0 keeps the prerequisite screen on the
    # terminal "missing" state instead of polling. That is what makes the
    # missing-Docker screen reachable for development and testing by pointing
    # ENKSTEIN_DOCKER_COMMAND/ENKSTEIN_DOCKER_APP at paths that do not exist,
    # with no need to uninstall Docker or remove any Docker data.
    local install_attempts="${ENKSTEIN_DOCKER_INSTALL_ATTEMPTS:-300}"
    if [ "$install_attempts" -le 0 ]; then
      return 2
    fi
    docker_state "installing" "Docker Desktop installation started from the official flow; waiting for the engine..."
    if wait_for_docker "$install_attempts" "${ENKSTEIN_DOCKER_INTERVAL:-2}"; then
      docker_state "healthy" "Docker Desktop engine is running."
      return 0
    fi
    # Falling back to "missing" rather than a generic timeout keeps the install
    # action on screen: the engine is still absent, so installing it is the
    # only useful next step.
    docker_state "missing" "Docker Desktop is still not installed. Install it, then retry."
    return 2
  fi

  if docker_healthy; then
    docker_state "healthy" "Docker Desktop engine is running."
    return 0
  fi

  if docker_desktop_running; then
    docker_state "unhealthy" "Docker Desktop is running but its engine is unhealthy."
  else
    docker_state "stopped" "Docker Desktop is installed but its engine is stopped."
  fi
  open_docker
  if wait_for_docker "${ENKSTEIN_DOCKER_ATTEMPTS:-60}" "${ENKSTEIN_DOCKER_INTERVAL:-2}"; then
    docker_state "healthy" "Docker Desktop engine is running."
    return 0
  fi

  docker_state "timeout" "Docker Desktop did not become healthy before the startup timeout."
  return 3
}
