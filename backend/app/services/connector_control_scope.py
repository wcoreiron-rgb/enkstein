"""Which controls one connector is capable of proving, and how they stand now.

A connector's value is only legible when you can answer two different
questions about it:

1. Catalog scope -- which controls could this connector ever produce evidence
   for? That is a static property of the collector bindings.
2. Live standing -- of those controls, which passed, failed, or were never
   assessed *in this tenant*? That is per-tenant evidence and cannot live in a
   docs site, because only the deployment knows it.

Both are answered from the same binding so the two can never drift.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.adapters import registry
from app.models.control import Control
from app.services.control_collectors import (
    COLLECTORS,
    collector_ready,
    configured_connectors,
)
from app.services.control_evaluation import evaluate_controls


# Connector types that exist for a purpose other than reporting security state.
# Saying "no collector is bound yet" for a model provider implies a gap that
# will be closed later, which is misleading: an inference endpoint has no
# posture to assess. Naming the reason keeps the empty scope honest.
NON_ASSESSING_REASONS: dict[str, str] = {
    "openai": "model_provider",
    "azure_openai": "model_provider",
    "anthropic": "model_provider",
    "gemini": "model_provider",
    "ollama": "model_provider",
    "nvidia_nim": "model_provider",
    "email": "notification_channel",
}

_REASON_TEXT: dict[str, str] = {
    "model_provider": (
        "This is a Brain provider used for reasoning, not a security evidence "
        "source, so it does not assess controls. Its governance lives in Model "
        "Cortex and Trust Fabric."
    ),
    "notification_channel": (
        "This connector delivers notifications rather than reporting system "
        "state, so it does not assess controls."
    ),
    "action_only": (
        "This connector performs actions rather than reporting state, so it "
        "does not assess controls."
    ),
    "unbound": "No evidence collector is bound to this connector type yet.",
}


def non_assessing_reason(connector_type: str) -> str:
    """Why this connector legitimately assesses nothing, or 'unbound'."""
    canonical = registry.canonical(connector_type)
    for candidate in (connector_type, canonical):
        if candidate in NON_ASSESSING_REASONS:
            return NON_ASSESSING_REASONS[candidate]
    if registry.is_action_only(connector_type):
        return "action_only"
    return "unbound"


def evaluators_for_connector(connector_type: str) -> list[str]:
    """Collector keys this connector type can satisfy, alias-aware."""
    canonical = registry.canonical(connector_type)
    keys: list[str] = []
    for key, spec in COLLECTORS.items():
        declared = spec.get("connectors") or []
        candidates = {registry.canonical(item) for item in declared}
        if canonical in candidates or connector_type in declared:
            keys.append(key)
    return sorted(keys)


async def scope_for_connector(
    db: AsyncSession,
    connector_type: str,
    *,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """Catalog scope plus this tenant's live verdicts for one connector type."""
    evaluator_keys = evaluators_for_connector(connector_type)
    active = await configured_connectors(db, tenant_id=tenant_id)
    configured = registry.canonical(connector_type) in {
        registry.canonical(item) for item in active
    }

    collectors = [
        {
            "evaluator_key": key,
            "domain": COLLECTORS[key]["domain"],
            "description": COLLECTORS[key]["description"],
            # A collector is satisfiable by any one of several connectors, so
            # "ready" can be true through a sibling connector even when this
            # one is unconfigured. Both facts are reported rather than merged.
            "ready": collector_ready(key, active),
            "alternative_connectors": sorted(
                item
                for item in COLLECTORS[key]["connectors"]
                if registry.canonical(item) != registry.canonical(connector_type)
            ),
        }
        for key in evaluator_keys
    ]

    if not evaluator_keys:
        reason_code = non_assessing_reason(connector_type)
        return {
            "connector_type": connector_type,
            "canonical_type": registry.canonical(connector_type),
            "adapter_state": registry.coverage_state(connector_type),
            "configured": configured,
            "collectors": [],
            "controls": [],
            "counts": {"in_scope": 0, "pass": 0, "fail": 0, "not_assessed": 0},
            "reason_code": reason_code,
            "assesses_controls": False,
            "reason": _REASON_TEXT[reason_code],
        }

    rows = (
        await db.execute(select(Control).where(Control.evaluator_key.in_(evaluator_keys)))
    ).scalars().all()
    in_scope_ids = {row.control_id for row in rows}

    # Verdicts are read from the deterministic evaluator rather than recomputed
    # here, so this view can never disagree with a node's own page.
    evaluation = await evaluate_controls(db, tenant_id=tenant_id)
    verdicts = {
        item["control_id"]: item
        for item in evaluation.get("results", [])
        if item.get("control_id") in in_scope_ids
    }

    controls: list[dict[str, Any]] = []
    counts = {"in_scope": 0, "pass": 0, "fail": 0, "not_assessed": 0}
    for row in sorted(rows, key=lambda item: item.control_id):
        evaluated = verdicts.get(row.control_id) or {}
        verdict = str(evaluated.get("verdict") or "not_assessed")
        counts["in_scope"] += 1
        counts[verdict] = counts.get(verdict, 0) + 1
        controls.append(
            {
                "control_id": row.control_id,
                "title": row.title,
                "node": row.claw,
                "zt_pillar": row.zt_pillar,
                "severity": row.severity,
                "source": row.source,
                "evaluator_key": row.evaluator_key,
                "remediation_action": row.remediation_action,
                "recommendation_only": bool(row.recommendation_only),
                "verdict": verdict,
                "reason": evaluated.get("reason"),
            }
        )

    return {
        "connector_type": connector_type,
        "canonical_type": registry.canonical(connector_type),
        "adapter_state": registry.coverage_state(connector_type),
        "configured": configured,
        "assesses_controls": True,
        "collectors": collectors,
        "controls": controls,
        "counts": counts,
    }


async def catalog_scope(db: AsyncSession, *, tenant_id: str | None = None) -> dict[str, Any]:
    """Per-connector control counts for every connector bound to a collector."""
    connector_types = sorted(
        {item for spec in COLLECTORS.values() for item in spec.get("connectors") or []}
    )
    entries = []
    for connector_type in connector_types:
        scope = await scope_for_connector(db, connector_type, tenant_id=tenant_id)
        entries.append(
            {
                "connector_type": connector_type,
                "adapter_state": scope["adapter_state"],
                "configured": scope["configured"],
                "assesses_controls": scope.get("assesses_controls", False),
                "counts": scope["counts"],
                "evaluator_keys": [item["evaluator_key"] for item in scope["collectors"]],
            }
        )
    return {"connectors": entries, "total": len(entries)}
