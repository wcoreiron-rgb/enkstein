#!/usr/bin/env bash
# Marcellus startup entrypoint — migrations → seeds → uvicorn
# Seeds are best-effort: a failure is logged but won't block startup.

echo "╔══════════════════════════════════════════════════════╗"
echo "║          Marcellus — startup initialisation          ║"
echo "╚══════════════════════════════════════════════════════╝"

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

if alembic current 2>&1 | grep -q "(head)"; then
  echo "    Already at head — skipping."
elif schema_is_materialized; then
  echo "    Existing schema is complete — reconciling migration revision."
  alembic stamp head
else
  alembic upgrade head
fi
echo "✅  Migrations done."

# ── Helper: run a script, warn on failure, never abort ───────────────────────
run_script() {
  local script="$1"
  if [ -f "$script" ]; then
    python "$script" && echo "    ✓ $script" || echo "    ⚠️  $script failed (non-fatal)"
  else
    echo "    – $script not found, skipping"
  fi
}

# ── Inline column patches (idempotent ALTER TABLE) ───────────────────────────
echo ""
echo "🔧  Applying schema patches…"
python - <<'PYEOF'
import os, psycopg2
url = os.environ.get("DATABASE_URL_SYNC") or os.environ["DATABASE_URL"].replace("+asyncpg","")
conn = psycopg2.connect(url)
conn.autocommit = True
cur = conn.cursor()
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
        print(f"    skip: {e}")
cur.close()
conn.close()
PYEOF
echo "✅  Schema patches done."

# ── Schema migrations ─────────────────────────────────────────────────────────
echo ""
echo "🔄  Schema migration scripts…"
run_script migrate_connectors_v2.py
run_script migrate_policy_packs.py
run_script migrate_workflows.py
echo "✅  Schema migrations done."

# ── Seeds ─────────────────────────────────────────────────────────────────────
echo ""
echo "🌱  Seeding data…"
run_script seed_connectors.py
run_script seed_policies.py
run_script seed_policies_expanded.py
run_script seed_policy_packs.py
run_script seed_agents.py
run_script seed_workflows.py
run_script seed_example_orchestrations.py
run_script seed_triggers.py
run_script seed_skill_packs.py
run_script seed_exchange.py
run_script seed_exec_channels.py
run_script seed_profiles.py
run_script seed_memory.py
run_script seed_channel_gateway.py
echo "✅  Seeds done."

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
