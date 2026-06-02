#!/usr/bin/env bash
# Re-mirror the standalone governance modules from the backend into regentclaw-core.
# Run from repo root after changing any of the source modules.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DST="$ROOT/regentclaw-core/regentclaw_core"
declare -A MAP=(
  ["$ROOT/backend/app/services/ring_policy.py"]="ring_policy.py"
  ["$ROOT/backend/app/services/provenance.py"]="provenance.py"
  ["$ROOT/backend/app/claws/arcclaw/scanner.py"]="scanner.py"
)
for src in "${!MAP[@]}"; do
  dst="$DST/${MAP[$src]}"
  { echo "# NOTE: mirrored from ${src#$ROOT/} — keep in sync via scripts/sync_core.sh."
    echo "# This module is intentionally dependency-light (stdlib + cryptography) so it"
    echo "# can run embedded with no RegentClaw server."
    cat "$src"; } > "$dst"
  echo "synced ${MAP[$src]}"
done
