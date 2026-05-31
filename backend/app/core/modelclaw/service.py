from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.modelclaw.schemas import ModelProfileCreate

_PROVIDERS: dict[str, dict[str, Any]] = {
    "nvidia_nim": {"enabled": True, "default_model": "meta/llama-3.3-70b-instruct", "supports_tool_calling": True},
    "ollama": {"enabled": True, "default_model": "qwen2.5:14b-instruct", "supports_tool_calling": True},
    "azure_openai": {"enabled": True, "default_model": "gpt-4o-mini", "supports_tool_calling": True},
    "openai": {"enabled": True, "default_model": "gpt-4.1-mini", "supports_tool_calling": True},
    "anthropic": {"enabled": True, "default_model": "claude-3-5-sonnet", "supports_tool_calling": True},
    "gemini": {"enabled": False, "default_model": "gemini-2.5-pro", "supports_tool_calling": True},
    "vllm_local": {"enabled": False, "default_model": "local/default", "supports_tool_calling": False},
}

_PROFILES: dict[str, dict[str, Any]] = {
    "nim_fast_reasoning": {
        "name": "nim_fast_reasoning",
        "provider": "nvidia_nim",
        "model": "meta/llama-3.3-70b-instruct",
        "allowed_claws": ["threatclaw", "identityclaw", "cloudclaw", "arcclaw"],
        "allowed_data_classes": ["public", "internal", "confidential"],
        "temperature": 0.2,
        "max_tokens": 4000,
        "tool_calling": True,
        "requires_redaction": True,
        "fallback_profile": "ollama_local_fallback",
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
    "ollama_local_fallback": {
        "name": "ollama_local_fallback",
        "provider": "ollama",
        "model": "qwen2.5:14b-instruct",
        "allowed_claws": ["arcclaw", "threatclaw"],
        "allowed_data_classes": ["public", "internal"],
        "temperature": 0.2,
        "max_tokens": 3000,
        "tool_calling": True,
        "requires_redaction": True,
        "fallback_profile": None,
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
    "swarm_judge_profile": {
        "name": "swarm_judge_profile",
        "provider": "nvidia_nim",
        "model": "meta/llama-3.3-70b-instruct",
        "allowed_claws": ["swarm_judge"],
        "allowed_data_classes": ["public", "internal", "confidential"],
        "temperature": 0.1,
        "max_tokens": 3000,
        "tool_calling": False,
        "requires_redaction": True,
        "fallback_profile": "ollama_local_fallback",
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
}

_MODEL_CALLS: list[dict[str, Any]] = []
_STATE_PATH = Path(".state/modelclaw_state.json")


def _serialize_dt(v: Any) -> Any:
    if isinstance(v, datetime):
        return v.isoformat()
    return v


def _persist_state() -> None:
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "profiles": {
                k: {pk: _serialize_dt(pv) for pk, pv in v.items()}
                for k, v in _PROFILES.items()
            },
            "calls": [
                {ck: _serialize_dt(cv) for ck, cv in c.items()}
                for c in _MODEL_CALLS[:500]
            ],
        }
        _STATE_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        # persistence is best-effort and should not block runtime routing
        pass


def _load_state() -> None:
    if not _STATE_PATH.exists():
        return
    try:
        raw = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
        profiles = raw.get("profiles", {})
        calls = raw.get("calls", [])
        for name, profile in profiles.items():
            created_at = profile.get("created_at")
            if isinstance(created_at, str):
                try:
                    profile["created_at"] = datetime.fromisoformat(created_at)
                except ValueError:
                    profile["created_at"] = datetime.utcnow()
            profile.setdefault("tenant_id", "global")
            _PROFILES[name] = profile
        _MODEL_CALLS.clear()
        for row in calls:
            ts = row.get("timestamp")
            if isinstance(ts, str):
                try:
                    row["timestamp"] = datetime.fromisoformat(ts)
                except ValueError:
                    row["timestamp"] = datetime.utcnow()
            row.setdefault("tenant_id", "global")
            _MODEL_CALLS.append(row)
    except Exception:
        pass


_load_state()


def list_providers() -> list[dict[str, Any]]:
    return [{"provider": k, **v} for k, v in sorted(_PROVIDERS.items())]


def list_profiles(tenant_id: str = "global") -> list[dict[str, Any]]:
    return [p for p in _PROFILES.values() if p.get("tenant_id", "global") == tenant_id]


def get_profile(name: str | None, tenant_id: str = "global") -> dict[str, Any] | None:
    if not name:
        d = _PROFILES.get("nim_fast_reasoning")
        return d if d and d.get("tenant_id", "global") == tenant_id else None
    d = _PROFILES.get(name)
    return d if d and d.get("tenant_id", "global") == tenant_id else None


def upsert_profile(payload: ModelProfileCreate) -> dict[str, Any]:
    row = payload.model_dump()
    row["created_at"] = datetime.utcnow()
    _PROFILES[payload.name] = row
    _persist_state()
    return row


def record_model_call(row: dict[str, Any]) -> dict[str, Any]:
    entry = {"id": f"mc_{uuid4().hex[:12]}", "timestamp": datetime.utcnow(), **row}
    _MODEL_CALLS.insert(0, entry)
    if len(_MODEL_CALLS) > 500:
        del _MODEL_CALLS[500:]
    _persist_state()
    return entry


def list_model_calls(limit: int = 50, tenant_id: str = "global") -> list[dict[str, Any]]:
    rows = [r for r in _MODEL_CALLS if r.get("tenant_id", "global") == tenant_id]
    return rows[: max(1, min(limit, 500))]
