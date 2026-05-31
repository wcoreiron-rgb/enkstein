from __future__ import annotations

from typing import Any


SWARM_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "FAST_TRIAGE": {
        "parallelism": 6,
        "task_type": "analyze",
        "classification": "internal",
        "requires_approval_for_actions": False,
        "model_profile": "swarm_judge_fast",
    },
    "DEEP_INVESTIGATION": {
        "parallelism": 4,
        "task_type": "investigate",
        "classification": "confidential",
        "requires_approval_for_actions": True,
        "model_profile": "swarm_judge_strong",
    },
    "INCIDENT_RESPONSE": {
        "parallelism": 8,
        "task_type": "investigate",
        "classification": "confidential",
        "requires_approval_for_actions": True,
        "model_profile": "swarm_judge_incident",
    },
    "AUTONOMOUS_LOW_RISK": {
        "parallelism": 4,
        "task_type": "analyze",
        "classification": "internal",
        "requires_approval_for_actions": False,
        "model_profile": "swarm_judge_fast",
    },
    "EMERGENCY_CONTAINMENT": {
        "parallelism": 10,
        "task_type": "containment",
        "classification": "restricted",
        "requires_approval_for_actions": True,
        "model_profile": "swarm_judge_emergency",
    },
}


def apply_swarm_profile_defaults(config: dict[str, Any]) -> dict[str, Any]:
    """
    Merge profile defaults into a swarm config dict.
    Caller-provided values always win over profile defaults.
    """
    profile = str(config.get("profile", "FAST_TRIAGE")).upper()
    defaults = SWARM_PROFILE_DEFAULTS.get(profile, {})
    merged = {**defaults, **config}
    merged["profile"] = profile
    return merged

