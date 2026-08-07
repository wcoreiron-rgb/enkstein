"""Read the runtime's durable database preparation status."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


DEFAULT_STATUS_PATH = Path("/app/.state/data_preparation.json")
VALID_STATUSES = frozenset({"running", "ready", "degraded"})


def _status_path() -> Path:
    configured = os.environ.get("ENKSTEIN_PREPARATION_STATUS_FILE")
    return Path(configured) if configured else DEFAULT_STATUS_PATH


def _unavailable_status(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "ready": False,
        "completed": False,
        "started_at": None,
        "finished_at": None,
        "failure_count": 0,
        "failures": [],
    }


def read_preparation_status() -> dict[str, Any]:
    """Return a bounded status payload without exposing arbitrary file content."""
    path = _status_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _unavailable_status("unknown")
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _unavailable_status("invalid")

    status = payload.get("status")
    failures = payload.get("failures")
    if status not in VALID_STATUSES or not isinstance(failures, list):
        return _unavailable_status("invalid")

    normalized_failures = []
    for failure in failures[:50]:
        if not isinstance(failure, dict):
            continue
        normalized_failures.append(
            {
                "phase": str(failure.get("phase", "unknown"))[:64],
                "name": str(failure.get("name", "unknown"))[:255],
                "reason": str(failure.get("reason", "diagnostic unavailable"))[:4000],
            }
        )

    return {
        "status": status,
        "ready": status == "ready" and payload.get("ready") is True,
        "completed": payload.get("completed") is True,
        "started_at": payload.get("started_at"),
        "finished_at": payload.get("finished_at"),
        "failure_count": len(normalized_failures),
        "failures": normalized_failures,
    }
