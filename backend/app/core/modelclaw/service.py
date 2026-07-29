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
    # Azure remains available through the legacy sensitivity router, but the
    # Model Cortex profile bridge has no native Azure adapter yet. Keep it
    # visible but disabled rather than claiming executable readiness.
    "azure_openai": {"enabled": False, "default_model": "gpt-4o-mini", "supports_tool_calling": True},
    "openai": {"enabled": True, "default_model": "gpt-4.1-mini", "supports_tool_calling": True},
    "anthropic": {"enabled": True, "default_model": "claude-3-5-sonnet", "supports_tool_calling": True},
    "gemini": {"enabled": True, "default_model": "gemini-2.5-flash", "supports_tool_calling": True},
    "vllm_local": {"enabled": False, "default_model": "local/default", "supports_tool_calling": False},
}

_PROFILES: dict[str, dict[str, Any]] = {
    "nim_fast_reasoning": {
        "name": "nim_fast_reasoning",
        "provider": "nvidia_nim",
        "model": "meta/llama-3.3-70b-instruct",
        "allowed_models": [
            "meta/llama-3.3-70b-instruct",
            "meta/llama-3.1-70b-instruct",
            "nvidia/llama-3.1-nemotron-70b-instruct",
            "nvidia/llama-3.3-nemotron-super-49b-v1",
            "mistralai/mistral-large-2-instruct",
            "mistralai/mistral-nemo-12b-instruct",
            "qwen/qwen2.5-72b-instruct",
            "meta/llama-3.1-8b-instruct",
        ],
        "allowed_claws": ["executive", "threatclaw", "identityclaw", "cloudclaw", "arcclaw"],
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
        # An empty allowlist means any model reported by the local Ollama runtime.
        "allowed_models": [],
        # swarm_judge is included so cross-node synthesis and control analysis
        # still run on the local Brain when no cloud provider is configured.
        # Without it the judge profile's own fallback is rejected here, and an
        # offline deployment loses AI analysis entirely.
        "allowed_claws": ["executive", "arcclaw", "threatclaw", "swarm_judge"],
        "allowed_data_classes": ["public", "internal", "confidential", "restricted", "top_secret"],
        "temperature": 0.2,
        "max_tokens": 3000,
        "tool_calling": True,
        "requires_redaction": True,
        "fallback_profile": None,
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
    "ollama_cowork_author": {
        "name": "ollama_cowork_author",
        "provider": "ollama",
        # Qwen 2.5 7B is a practical local coding model on ordinary developer
        # hardware. The invocation pins this model explicitly so a global
        # fallback preference cannot silently turn a file-authoring turn into
        # a different local Brain.
        "model": "qwen2.5:7b",
        "allowed_models": [],
        "allowed_claws": ["executive"],
        "allowed_data_classes": ["public", "internal", "confidential", "restricted", "top_secret"],
        "temperature": 0.1,
        "max_tokens": 6000,
        "tool_calling": False,
        "requires_redaction": True,
        "fallback_profile": None,
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
    "gemma_scanner": {
        "name": "gemma_scanner",
        "provider": "ollama",
        "model": "gemma2:9b",
        # Local Ollama Gemma only — distinct from any Gemini API/CLI provider,
        # which is intentionally not offered under this profile name. An empty
        # allowlist means any model reported by the local Ollama runtime, so a
        # host without gemma2:9b installed still resolves to a real installed
        # model rather than failing on a missing exact tag.
        "allowed_models": [],
        "allowed_claws": ["executive", "arcclaw"],
        # Never leaves the loopback-local Ollama runtime, so every
        # classification level is safe for this profile specifically.
        "allowed_data_classes": ["public", "internal", "confidential", "restricted", "top_secret"],
        "temperature": 0.1,
        "max_tokens": 1200,
        "tool_calling": False,
        "requires_redaction": True,
        "fallback_profile": None,
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
    "swarm_judge_profile": {
        "name": "swarm_judge_profile",
        "provider": "nvidia_nim",
        "model": "meta/llama-3.3-70b-instruct",
        "allowed_models": ["meta/llama-3.3-70b-instruct"],
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
    "gemini_general": {
        "name": "gemini_general",
        "provider": "gemini",
        "model": "gemini-2.5-flash",
        "allowed_models": ["gemini-2.5-flash", "gemini-2.5-pro"],
        "allowed_claws": ["executive", "arcclaw"],
        "allowed_data_classes": ["public", "internal", "confidential"],
        "temperature": 0.2,
        "max_tokens": 4000,
        "tool_calling": True,
        "requires_redaction": True,
        "fallback_profile": "ollama_local_fallback",
        "tenant_id": "global",
        "created_at": datetime.utcnow(),
    },
}

_MODEL_CALLS: list[dict[str, Any]] = []
_STATE_PATH = Path(".state/modelclaw_state.json")

# Snapshot of the profiles this build ships with, taken before any persisted
# state is loaded. Policy allow-lists are read back from here so saved state
# cannot pin a deployment to an older profile's capabilities.
_BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    key: dict(value) for key, value in _PROFILES.items()
}


def _profile_storage_key(tenant_id: str, name: str) -> str:
    """Keep tenant-owned profiles distinct without changing their public names."""
    return name if tenant_id == "global" else f"{tenant_id}:{name}"


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
            profile.setdefault("allowed_models", [profile["model"]])
            public_name = profile.get("name", name)
            key = _profile_storage_key(profile["tenant_id"], public_name)
            builtin = _BUILTIN_PROFILES.get(key)
            if builtin is not None:
                # A persisted copy must not freeze a built-in profile at the
                # capabilities it shipped with. Operator-tunable fields are
                # restored from disk; the policy allow-lists stay owned by the
                # code, so a released capability change reaches deployments
                # that already have saved state.
                merged = dict(builtin)
                for field in ("model", "allowed_models", "temperature", "max_tokens",
                              "provider", "fallback_profile", "created_at"):
                    if field in profile:
                        merged[field] = profile[field]
                profile = merged
            _PROFILES[key] = profile
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
for _executive_profile in ("nim_fast_reasoning", "ollama_local_fallback"):
    _allowed = _PROFILES.get(_executive_profile, {}).setdefault("allowed_claws", [])
    if "executive" not in _allowed:
        _allowed.append("executive")
_local_classes = _PROFILES.get("ollama_local_fallback", {}).setdefault("allowed_data_classes", [])
for _data_class in ("confidential", "restricted", "top_secret"):
    if _data_class not in _local_classes:
        _local_classes.append(_data_class)


def list_providers() -> list[dict[str, Any]]:
    return [{"provider": k, **v} for k, v in sorted(_PROVIDERS.items())]


def list_profiles(tenant_id: str = "global") -> list[dict[str, Any]]:
    return [p for p in _PROFILES.values() if p.get("tenant_id", "global") == tenant_id]


def get_profile(name: str | None, tenant_id: str = "global") -> dict[str, Any] | None:
    if not name:
        d = _PROFILES.get(_profile_storage_key(tenant_id, "nim_fast_reasoning"))
        return d if d and d.get("tenant_id", "global") == tenant_id else None
    d = _PROFILES.get(_profile_storage_key(tenant_id, name))
    return d if d and d.get("tenant_id", "global") == tenant_id else None


def upsert_profile(payload: ModelProfileCreate) -> dict[str, Any]:
    row = payload.model_dump()
    row["created_at"] = datetime.utcnow()
    _PROFILES[_profile_storage_key(payload.tenant_id, payload.name)] = row
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
