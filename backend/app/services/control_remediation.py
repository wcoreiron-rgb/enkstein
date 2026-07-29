"""Connect failing controls to remediation, and verify the fix afterwards.

A control that can only report FAIL is an alert, not a control. This module
closes the loop: a failing control proposes the remediation action its
definition declares, that action runs through the existing governed engine,
and the control is then re-evaluated so the operator sees whether the fix
actually worked.

Two rules keep this honest:

* A control only proposes an action it explicitly declares. Enkstein never
  infers a destructive action from a finding's text.
* Verification is a fresh evaluation after the action completes. An executed
  action is not evidence that the control now passes.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.control import Control
from app.models.finding import Finding
from app.services.control_evaluation import Verdict, evaluate_controls

logger = logging.getLogger("controls.remediation")

# Which provider executes a node's remediation. The remediation engine
# dispatches on provider, so a control has to name one to be actionable.
NODE_REMEDIATION_PROVIDER: dict[str, str] = {
    "identityclaw": "entra_id",
    "accessclaw": "entra_id",
    "userclaw": "entra_id",
    "insiderclaw": "entra_id",
    "endpointclaw": "defender_endpoint",
    "cloudclaw": "aws_iam",
    "devclaw": "github",
}


async def proposals(db: AsyncSession, *, claw: str | None = None) -> dict[str, Any]:
    """Failing controls that declare a remediation action, with their evidence."""
    evaluation = await evaluate_controls(db, claw=claw)
    failing = [item for item in evaluation["results"] if item["verdict"] == Verdict.FAIL.value]

    actionable: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    for item in failing:
        action = item.get("remediation_action")
        provider = NODE_REMEDIATION_PROVIDER.get(item.get("claw") or "")
        entry = {
            "control_id": item["control_id"],
            "title": item["title"],
            "claw": item["claw"],
            "severity": item["severity"],
            "zt_pillar": item["zt_pillar"],
            "evidence_count": item["evidence_count"],
            "example_finding_id": item.get("example_finding_id"),
            "action_type": action,
            "provider": provider,
        }
        if action and provider:
            actionable.append(entry)
        else:
            entry["reason"] = (
                "This control has no declared remediation action."
                if not action
                else f"No remediation provider is mapped for {item.get('claw')}."
            )
            advisory.append(entry)

    return {
        "claw": claw,
        "failing": len(failing),
        "actionable": actionable,
        "advisory_only": advisory,
        "generated_at": datetime.utcnow().isoformat(),
    }


async def remediate_control(
    db: AsyncSession,
    *,
    control_id: str,
    triggered_by: str = "operator",
) -> dict[str, Any]:
    """Propose the declared remediation for one failing control.

    The action is created through the governed remediation engine, which
    applies its own risk classification and approval gate. Nothing here
    bypasses that: a high-risk action still lands in PENDING_APPROVAL.
    """
    control = (await db.execute(
        select(Control).where(Control.control_id == control_id)
    )).scalars().first()
    if control is None:
        return {"status": "unknown_control", "control_id": control_id}
    if not control.remediation_action:
        return {
            "status": "recommendation_only",
            "control_id": control_id,
            "detail": "This control declares no remediation action; guidance only.",
            "remediation": control.remediation,
        }

    provider = NODE_REMEDIATION_PROVIDER.get(control.claw or "")
    if not provider:
        return {
            "status": "no_provider",
            "control_id": control_id,
            "detail": f"No remediation provider is mapped for {control.claw}.",
        }

    finding = (await db.execute(
        select(Finding)
        .where(Finding.control_id == control_id, Finding.status == "open")
        .order_by(desc(Finding.risk_score))
        .limit(1)
    )).scalars().first()
    if finding is None:
        return {
            "status": "not_failing",
            "control_id": control_id,
            "detail": "No open finding violates this control, so there is nothing to remediate.",
        }

    from app.services.remediation.engine import execute_remediation

    action = await execute_remediation(
        {
            "provider": provider,
            "action_type": control.remediation_action,
            "target_id": finding.resource_id or str(finding.id),
            "target_type": finding.resource_type or "resource",
            "target_label": finding.title[:200],
            "parameters": {"control_id": control_id, "source": "control_remediation"},
        },
        db,
        finding_id=finding.id,
        triggered_by=triggered_by,
    )
    status = action.status.value if hasattr(action.status, "value") else str(action.status)
    return {
        "status": "created",
        "control_id": control_id,
        "action_id": str(action.id),
        "action_type": control.remediation_action,
        "provider": provider,
        "risk_level": action.risk_level,
        "requires_approval": action.requires_approval,
        "remediation_status": status,
        "finding_id": str(finding.id),
        # The control is not re-evaluated here. Verification happens after the
        # action actually executes, via verify_after_remediation.
        "verification": "pending",
    }


async def verify_after_remediation(db: AsyncSession, *, control_id: str) -> dict[str, Any]:
    """Re-evaluate a control after remediation and report the new verdict."""
    evaluation = await evaluate_controls(db, control_id=control_id)
    result = evaluation["results"][0] if evaluation["results"] else None
    if result is None:
        return {"control_id": control_id, "status": "unknown_control"}
    return {
        "control_id": control_id,
        "verdict": result["verdict"],
        "reason": result["reason"],
        "evidence_count": result["evidence_count"],
        "remediated": result["verdict"] == Verdict.PASS.value,
        "note": (
            "A rescan must run before this reflects the post-remediation state."
            if result["verdict"] == Verdict.NOT_ASSESSED.value
            else None
        ),
        "verified_at": datetime.utcnow().isoformat(),
    }
