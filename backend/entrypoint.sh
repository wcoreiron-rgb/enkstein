#!/usr/bin/env bash
# Marcellus startup entrypoint — migrations → seeds → uvicorn
# Seeds are best-effort: a failure is logged but won't block startup.

echo "╔══════════════════════════════════════════════════════╗"
echo "║          Marcellus — startup initialisation          ║"
echo "╚══════════════════════════════════════════════════════╝"

# ── Preparation status and diagnostics ───────────────────────────────────────
PREPARATION_STATUS_FILE="${ENKSTEIN_PREPARATION_STATUS_FILE:-/app/.state/data_preparation.json}"
PREPARATION_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
preparation_failure_phases=()
preparation_failure_names=()
preparation_failure_reasons=()

sanitize_output() {
  local output_file="$1"
  python - "$output_file" <<'PYEOF'
import os
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")

# Remove exact values of known sensitive environment variables first. Sorting
# longest-first prevents a shorter value from leaving part of a longer secret.
sensitive_markers = ("PASSWORD", "SECRET", "TOKEN", "API_KEY", "CREDENTIAL")
sensitive_keys = {"DATABASE_URL", "DATABASE_URL_SYNC", "REDIS_URL"}
secret_values = {
    value
    for key, value in os.environ.items()
    if value
    and (
        key.upper() in sensitive_keys
        or any(marker in key.upper() for marker in sensitive_markers)
    )
}
for value in sorted(secret_values, key=len, reverse=True):
    text = text.replace(value, "[redacted]")

# Catch credential-bearing URLs and common key/value forms even when a tool
# reformats a connection string instead of printing the exact environment value.
text = re.sub(
    r"([a-z][a-z0-9+.-]*://)([^\s/@:]+):([^\s/@]+)@",
    r"\1[redacted]@",
    text,
    flags=re.IGNORECASE,
)
text = re.sub(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\s*([=:])\s*([^\s,;]+)",
    r"\1\2[redacted]",
    text,
)
text = re.sub(
    r"(?im)^\s*\[parameters:.*$",
    "[parameters: redacted]",
    text,
)

lines = [line.rstrip()[:500] for line in text.splitlines() if line.strip()]
diagnostic = "\n".join(lines[-12:])
print(diagnostic[:4000] or "command failed without diagnostic output")
PYEOF
}

record_preparation_failure() {
  preparation_failure_phases+=("$1")
  preparation_failure_names+=("$2")
  preparation_failure_reasons+=("$3")
}

run_preparation_command() {
  local name="$1"
  local phase="$2"
  local output_file
  local exit_code
  local reason
  shift 2

  output_file="$(mktemp)"
  if "$@" >"$output_file" 2>&1; then
    rm -f "$output_file"
    return 0
  else
    exit_code=$?
  fi

  reason="$(sanitize_output "$output_file")"
  rm -f "$output_file"
  record_preparation_failure "$phase" "$name" "exit $exit_code: $reason"
  echo "    ⚠️  $name failed (non-fatal; diagnostic captured)"
  return "$exit_code"
}

write_preparation_status() {
  local status="$1"
  local completed="$2"
  local finished_at="$3"
  local args=()
  local index

  for ((index = 0; index < ${#preparation_failure_names[@]}; index++)); do
    args+=(
      "${preparation_failure_phases[$index]}"
      "${preparation_failure_names[$index]}"
      "${preparation_failure_reasons[$index]}"
    )
  done

  if ! python - \
    "$PREPARATION_STATUS_FILE" \
    "$status" \
    "$completed" \
    "$PREPARATION_STARTED_AT" \
    "$finished_at" \
    "${args[@]}" <<'PYEOF'
import json
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
status = sys.argv[2]
completed = sys.argv[3] == "true"
started_at = sys.argv[4]
finished_at = sys.argv[5] or None
failure_args = sys.argv[6:]
failures = [
    {"phase": failure_args[index], "name": failure_args[index + 1], "reason": failure_args[index + 2]}
    for index in range(0, len(failure_args), 3)
]
payload = {
    "status": status,
    "ready": status == "ready",
    "completed": completed,
    "started_at": started_at,
    "finished_at": finished_at,
    "failure_count": len(failures),
    "failures": failures,
}

path.parent.mkdir(parents=True, exist_ok=True)
temporary_name = None
try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as temporary:
        temporary_name = temporary.name
        json.dump(payload, temporary, indent=2)
        temporary.write("\n")
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(temporary_name, path)
except Exception:
    if temporary_name:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
    raise
PYEOF
  then
    echo "    ⚠️  Could not write preparation status to $PREPARATION_STATUS_FILE"
    return 1
  fi
}

print_preparation_summary() {
  local failure_count=${#preparation_failure_names[@]}
  local finished_at
  local index

  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo ""
  echo "════════════════ Data preparation summary ════════════════"
  if [ "$failure_count" -eq 0 ]; then
    echo "✅  Data preparation ready: 0 failures."
    write_preparation_status "ready" "true" "$finished_at"
  else
    echo "⚠️  DATA PREPARATION DEGRADED: $failure_count failure(s)."
    for ((index = 0; index < failure_count; index++)); do
      echo "    $((index + 1)). [${preparation_failure_phases[$index]}] ${preparation_failure_names[$index]}"
      while IFS= read -r line; do
        echo "       $line"
      done <<< "${preparation_failure_reasons[$index]}"
    done
    write_preparation_status "degraded" "true" "$finished_at"
  fi
  echo "    Status: $PREPARATION_STATUS_FILE"
  echo "═══════════════════════════════════════════════════════════"
}

# A persisted status can describe a previous container run. Mark this run as in
# progress before touching the database so stale success is never reported.
write_preparation_status "running" "false" ""

# ── Wait for Postgres ─────────────────────────────────────────────────────────
echo ""
echo "⏳  Waiting for database…"
for i in $(seq 1 30); do
  python - <<'EOF' 2>/dev/null && break
import os, sys, psycopg2
url = os.environ.get("DATABASE_URL_SYNC") or os.environ["DATABASE_URL"].replace("+asyncpg","")
try:
    psycopg2.connect(url)
    sys.exit(0)
except Exception:
    sys.exit(1)
EOF
  echo "    (attempt $i/30) waiting 2s…"
  sleep 2
done
echo "✅  Database is ready."

# ── Alembic migrations ────────────────────────────────────────────────────────
echo ""
echo "📦  Running Alembic migrations…"

schema_is_materialized() {
  python - <<'PYEOF'
import os
import sys

import psycopg2

url = os.environ.get("DATABASE_URL_SYNC") or os.environ["DATABASE_URL"].replace("+asyncpg", "")
required_tables = (
    "customclaw_definitions",
    "remediation_actions",
    "remediation_playbooks",
)
with psycopg2.connect(url) as connection:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT to_regclass(%s) IS NOT NULL, "
            "to_regclass(%s) IS NOT NULL, "
            "to_regclass(%s) IS NOT NULL",
            tuple(f"public.{table}" for table in required_tables),
        )
        sys.exit(0 if all(cursor.fetchone()) else 1)
PYEOF
}

# A first launch starts from an empty database. The baseline revision is a no-op
# that assumes create_all already ran, so `alembic upgrade head` would reach the
# first revision with real DDL and fail on tables that do not exist yet --
# aborting before alembic_version is ever written and leaving every seed below
# to run against a schema-less database. Build the schema first, then stamp it,
# so migrations and seeds both see the tables they expect.
database_is_empty() {
  python - <<'PYEOF'
import os
import sys

import psycopg2

url = os.environ.get("DATABASE_URL_SYNC") or os.environ["DATABASE_URL"].replace("+asyncpg", "")
with psycopg2.connect(url) as connection:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"
        )
        sys.exit(0 if cursor.fetchone()[0] == 0 else 1)
PYEOF
}

if database_is_empty; then
  echo "    Empty database — creating the initial schema."
  if run_preparation_command "bootstrap_schema.py" "migration" python bootstrap_schema.py; then
    run_preparation_command "alembic stamp head" "migration" alembic stamp head
  else
    echo "    ⚠️  Schema bootstrap failed; falling back to migrations."
    run_preparation_command "alembic upgrade head" "migration" alembic upgrade head
  fi
elif alembic current 2>&1 | grep -q "(head)"; then
  echo "    Already at head — skipping."
elif schema_is_materialized; then
  echo "    Existing schema is complete — reconciling migration revision."
  run_preparation_command "alembic stamp head" "migration" alembic stamp head
else
  run_preparation_command "alembic upgrade head" "migration" alembic upgrade head
fi
echo "✅  Migrations attempted."

# ── Helper: run a script, warn on failure, never abort ───────────────────────
run_script() {
  local script="$1"
  local phase="$2"
  if [ -f "$script" ]; then
    if run_preparation_command "$script" "$phase" python "$script"; then
      echo "    ✓ $script"
    fi
  else
    echo "    – $script not found, skipping"
  fi
}

# ── Inline column patches (idempotent ALTER TABLE) ───────────────────────────
echo ""
echo "🔧  Applying schema patches…"
run_preparation_command "inline schema patches" "migration" python - <<'PYEOF'
import os
import sys

import psycopg2

url = os.environ.get("DATABASE_URL_SYNC") or os.environ["DATABASE_URL"].replace("+asyncpg","")
conn = psycopg2.connect(url)
conn.autocommit = True
cur = conn.cursor()
failures = []
patches = [
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_external BOOLEAN DEFAULT FALSE",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS endpoint_url VARCHAR(512)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS signing_secret VARCHAR(255)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS api_key_preview VARCHAR(64)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS allowed_scopes TEXT",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS endpoint_verified_at TIMESTAMPTZ",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS endpoint_last_error TEXT",
]
for sql in patches:
    try:
        cur.execute(sql)
        print(f"    ok: {sql[len('ALTER TABLE agents '):]}")
    except Exception as e:
        failures.append(str(e))
        print(f"    skip: {e}")
cur.close()
conn.close()
if failures:
    sys.exit(1)
PYEOF
echo "✅  Schema patches attempted."

# ── Schema migrations ─────────────────────────────────────────────────────────
echo ""
echo "🔄  Schema migration scripts…"
run_script migrate_connectors_v2.py migration
run_script migrate_policy_packs.py migration
run_script migrate_workflows.py migration
echo "✅  Schema migrations attempted."

# ── Seeds ─────────────────────────────────────────────────────────────────────
echo ""
echo "🌱  Seeding data…"
run_script seed_connectors.py seed
run_script seed_policies.py seed
run_script seed_policies_expanded.py seed
run_script seed_policy_packs.py seed
run_script seed_agents.py seed
run_script seed_workflows.py seed
run_script seed_example_orchestrations.py seed
run_script seed_triggers.py seed
run_script seed_skill_packs.py seed
run_script seed_exchange.py seed
run_script seed_exec_channels.py seed
run_script seed_profiles.py seed
run_script seed_memory.py seed
run_script seed_channel_gateway.py seed
echo "✅  Seeds attempted."

print_preparation_summary

# ── Start API ─────────────────────────────────────────────────────────────────
echo ""
echo "🚀  Starting Marcellus API on :8000"
echo ""

# --timeout-keep-alive must exceed the reverse proxy's idle socket reuse window.
# uvicorn's 5s default closes an idle keep-alive connection that the Next.js
# proxy has already selected for the next request, which surfaces in the browser
# as ECONNRESET -> a synthetic 500 on slow endpoints (AI advisory, scans) even
# though the handler itself returned 200.
uvicorn_args=(
  main:app
  --host 0.0.0.0
  --port 8000
  --timeout-keep-alive "${UVICORN_KEEP_ALIVE_TIMEOUT:-75}"
)
if [ "${UVICORN_RELOAD:-false}" = "true" ]; then
  echo "    Development reload enabled."
  uvicorn_args+=(--reload)
fi

exec uvicorn "${uvicorn_args[@]}"
