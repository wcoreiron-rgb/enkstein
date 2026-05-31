"""
RegentClaw — Remediation Engine REST API
Endpoints for managing approval queue, action history, and playbooks.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.remediation import RemediationAction, RemediationStatus, RemediationPlaybook
from app.services.remediation.engine import (
    approve_remediation,
    reject_remediation,
    rollback_remediation,
    execute_remediation,
)
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(prefix="/remediation", tags=["Remediation"])
logger = logging.getLogger("remediation_routes")


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class ApproveRequest(BaseModel):
    approved_by: str = "admin"


class RejectRequest(BaseModel):
    rejected_by: str = "admin"
    reason: str = "Rejected via UI"


class TriggerRequest(BaseModel):
    playbook_id: str | None = None
    finding_id: str | None = None
    action_spec: dict | None = None
    triggered_by: str = "manual"


def _validate_action_spec_shape(action_spec: dict[str, Any]) -> None:
    required = ["provider", "action_type", "target_type", "target_id"]
    missing = [k for k in required if not action_spec.get(k)]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"action_spec missing required fields: {', '.join(missing)}",
        )

    if action_spec.get("action_type") == "create_jira_ticket":
        params = action_spec.get("parameters")
        if not isinstance(params, dict):
            raise HTTPException(
                status_code=400,
                detail="create_jira_ticket requires parameters object",
            )
        required_ticket_params = ["project_key", "summary", "description"]
        missing_ticket = [k for k in required_ticket_params if not params.get(k)]
        if missing_ticket:
            raise HTTPException(
                status_code=400,
                detail=f"create_jira_ticket missing required parameters: {', '.join(missing_ticket)}",
            )
        project_key = str(params.get("project_key", "")).strip()
        summary = str(params.get("summary", "")).strip()
        description = str(params.get("description", "")).strip()
        if not project_key or not project_key.replace("_", "").replace("-", "").isalnum() or project_key.upper() != project_key:
            raise HTTPException(
                status_code=400,
                detail="create_jira_ticket project_key must be uppercase alphanumeric (dashes/underscores allowed)",
            )
        if len(summary) < 8:
            raise HTTPException(
                status_code=400,
                detail="create_jira_ticket summary must be at least 8 characters",
            )
        if len(description) < 16:
            raise HTTPException(
                status_code=400,
                detail="create_jira_ticket description must be at least 16 characters",
            )


def _action_to_dict(action: RemediationAction) -> dict:
    return {
        "id":                str(action.id),
        "finding_id":        str(action.finding_id) if action.finding_id else None,
        "workflow_run_id":   str(action.workflow_run_id) if action.workflow_run_id else None,
        "playbook_id":       action.playbook_id,
        "provider":          action.provider,
        "action_type":       action.action_type,
        "target_type":       action.target_type,
        "target_id":         action.target_id,
        "target_label":      action.target_label,
        "parameters":        json.loads(action.parameters) if action.parameters else {},
        "status":            action.status.value,
        "risk_level":        action.risk_level,
        "requires_approval": action.requires_approval,
        "triggered_by":      action.triggered_by,
        "approved_by":       action.approved_by,
        "rejected_reason":   action.rejected_reason,
        "approval_expires_at": action.approval_expires_at.isoformat() if action.approval_expires_at else None,
        "executed_at":       action.executed_at.isoformat() if action.executed_at else None,
        "completed_at":      action.completed_at.isoformat() if action.completed_at else None,
        "rollback_data":     json.loads(action.rollback_data) if action.rollback_data else None,
        "output":            json.loads(action.output) if action.output else None,
        "error":             action.error,
        "created_at":        action.created_at.isoformat() if action.created_at else None,
        "updated_at":        action.updated_at.isoformat() if action.updated_at else None,
    }


def _playbook_to_dict(pb: RemediationPlaybook) -> dict:
    return {
        "id":                      str(pb.id),
        "slug":                    pb.slug,
        "name":                    pb.name,
        "description":             pb.description,
        "trigger_claw":            pb.trigger_claw,
        "trigger_severity":        pb.trigger_severity,
        "trigger_category":        pb.trigger_category,
        "trigger_keywords":        json.loads(pb.trigger_keywords) if pb.trigger_keywords else [],
        "actions":                 json.loads(pb.actions_json) if pb.actions_json else [],
        "is_active":               pb.is_active,
        "requires_approval":       pb.requires_approval,
        "auto_rollback_on_failure": pb.auto_rollback_on_failure,
        "run_count":               pb.run_count,
        "created_at":              pb.created_at.isoformat() if pb.created_at else None,
    }


# ─── Action endpoints ─────────────────────────────────────────────────────────

@router.get("/actions")
async def list_actions(
    status: str | None = Query(None, description="Filter by status"),
    provider: str | None = Query(None, description="Filter by provider"),
    risk_level: str | None = Query(None, description="Filter by risk_level"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """List all remediation actions with optional filters."""
    query = select(RemediationAction)
    if status:
        try:
            query = query.where(RemediationAction.status == RemediationStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    if provider:
        query = query.where(RemediationAction.provider == provider)
    if risk_level:
        query = query.where(RemediationAction.risk_level == risk_level)

    query = query.order_by(RemediationAction.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(query)
    actions = result.scalars().all()

    # Total count
    count_q = select(func.count(RemediationAction.id))
    if status:
        count_q = count_q.where(RemediationAction.status == RemediationStatus(status))
    if provider:
        count_q = count_q.where(RemediationAction.provider == provider)
    count_result = await db.execute(count_q)
    total = count_result.scalar_one()

    return {
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "actions": [_action_to_dict(a) for a in actions],
    }


@router.get("/actions/{action_id}")
async def get_action(action_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a single remediation action by ID."""
    result = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = result.scalar_one_or_none()
    if action is None:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    return _action_to_dict(action)


@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: UUID,
    body: ApproveRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Approve a pending remediation action and execute it.
    Approver identity is taken from the JWT — the body.approved_by field is ignored."""
    # Always use the authenticated identity — never trust the client-supplied field
    approver = current_user.get("sub", "unknown")

    # Load action to check Trust Fabric ring-policy decision before approving
    pre_result = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    pre_action = pre_result.scalar_one_or_none()
    if pre_action is not None:
        tf_decision = await enforce(
            db,
            ActionRequest(
                module="remediation",
                actor_id=current_user.get("sub", "unknown"),
                actor_name=current_user.get("sub", "unknown"),
                actor_type="human",
                action=pre_action.action_type or "remediation_action",
                target=pre_action.target_id,
                target_type=pre_action.target_type,
                context={
                    "channel": "remediation",
                    "enforce_ring_policy": True,
                    "caller_role": current_user.get("role", "viewer"),
                    "trust_score": 50.0,
                },
            ),
        )
        if not tf_decision.allowed and tf_decision.outcome.value == "blocked":
            raise HTTPException(403, detail={
                "policy_name": tf_decision.policy_name,
                "deny_reason": tf_decision.reason,
            })
        if tf_decision.outcome.value == "requires_approval":
            raise HTTPException(409, detail={
                "policy_name": tf_decision.policy_name,
                "deny_reason": tf_decision.reason,
            })

    try:
        action = await approve_remediation(action_id, approver, db)
        return _action_to_dict(action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Error approving action %s", action_id)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/actions/{action_id}/reject")
async def reject_action(
    action_id: UUID,
    body: RejectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Reject a pending remediation action."""
    # Rejecter identity always from JWT
    rejecter = current_user.get("sub", "unknown")
    try:
        action = await reject_remediation(action_id, rejecter, body.reason, db)
        return _action_to_dict(action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Error rejecting action %s", action_id)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/actions/{action_id}/rollback")
async def rollback_action(
    action_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Roll back a completed remediation action."""
    try:
        action = await rollback_remediation(action_id, db)
        return _action_to_dict(action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Error rolling back action %s", action_id)
        raise HTTPException(status_code=500, detail=str(exc))


# ─── Playbook endpoints ───────────────────────────────────────────────────────

@router.get("/playbooks")
async def list_playbooks(db: AsyncSession = Depends(get_db)):
    """List all remediation playbooks. Seeds built-ins on first call."""
    try:
        from app.services.remediation.playbooks import seed_builtin_playbooks
        await seed_builtin_playbooks(db)
    except Exception as exc:
        logger.warning("Playbook seeding error (non-fatal): %s", exc)

    result = await db.execute(
        select(RemediationPlaybook).order_by(RemediationPlaybook.created_at.asc())
    )
    playbooks = result.scalars().all()
    return {"playbooks": [_playbook_to_dict(pb) for pb in playbooks]}


@router.post("/playbooks/{playbook_id}/toggle")
async def toggle_playbook(playbook_id: str, db: AsyncSession = Depends(get_db)):
    """Enable or disable a playbook."""
    # Accept both UUID and slug
    try:
        uid = UUID(playbook_id)
        result = await db.execute(select(RemediationPlaybook).where(RemediationPlaybook.id == uid))
    except ValueError:
        result = await db.execute(
            select(RemediationPlaybook).where(RemediationPlaybook.slug == playbook_id)
        )

    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=404, detail="Playbook not found")

    playbook.is_active = not playbook.is_active
    await db.commit()
    return _playbook_to_dict(playbook)


# ─── Manual trigger endpoint ──────────────────────────────────────────────────

@router.post("/trigger")
async def manual_trigger(body: TriggerRequest, db: AsyncSession = Depends(get_db)):
    """
    Manually trigger a playbook against a finding, or execute a single action_spec.
    """
    actions_created: list[dict] = []

    if body.finding_id and body.playbook_id:
        # Load finding and trigger the specific playbook
        from app.models.finding import Finding
        finding_result = await db.execute(
            select(Finding).where(Finding.id == UUID(body.finding_id))
        )
        finding = finding_result.scalar_one_or_none()
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")

        # Load playbook
        try:
            pb_id = UUID(body.playbook_id)
            pb_result = await db.execute(select(RemediationPlaybook).where(RemediationPlaybook.id == pb_id))
        except ValueError:
            pb_result = await db.execute(
                select(RemediationPlaybook).where(RemediationPlaybook.slug == body.playbook_id)
            )
        playbook = pb_result.scalar_one_or_none()
        if playbook is None:
            raise HTTPException(status_code=404, detail="Playbook not found")

        actions_spec = json.loads(playbook.actions_json) if playbook.actions_json else []
        from app.services.remediation.playbooks import _resolve_target, _build_context
        context = _build_context(finding)

        for action_spec in actions_spec:
            target_id = _resolve_target(action_spec.get("target_from"), finding, finding.resource_id or "manual")
            params    = dict(action_spec.get("params", {}))
            params["_context"] = context
            action = await execute_remediation(
                action_spec={
                    "provider":    action_spec.get("provider", "generic"),
                    "action_type": action_spec.get("action_type", "send_slack_alert"),
                    "target_id":   target_id,
                    "target_type": action_spec.get("target_type", "unknown"),
                    "target_label": target_id,
                    "parameters":  params,
                },
                db=db,
                finding_id=finding.id,
                playbook_id=str(playbook.id),
                triggered_by=body.triggered_by,
            )
            actions_created.append(_action_to_dict(action))

    elif body.action_spec:
        _validate_action_spec_shape(body.action_spec)
        action = await execute_remediation(
            action_spec=body.action_spec,
            db=db,
            triggered_by=body.triggered_by,
        )
        actions_created.append(_action_to_dict(action))
    else:
        raise HTTPException(
            status_code=400,
            detail="Must provide either (finding_id + playbook_id) or action_spec",
        )

    return {"triggered": len(actions_created), "actions": actions_created}


# ─── Stats endpoint ───────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Summary statistics for the remediation dashboard."""
    now   = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    async def _count(status: RemediationStatus) -> int:
        r = await db.execute(
            select(func.count(RemediationAction.id)).where(RemediationAction.status == status)
        )
        return r.scalar_one() or 0

    async def _count_today(status: RemediationStatus) -> int:
        r = await db.execute(
            select(func.count(RemediationAction.id)).where(
                and_(
                    RemediationAction.status == status,
                    RemediationAction.completed_at >= today,
                )
            )
        )
        return r.scalar_one() or 0

    pending   = await _count(RemediationStatus.PENDING_APPROVAL)
    executing = await _count(RemediationStatus.EXECUTING)
    completed_today = await _count_today(RemediationStatus.COMPLETED)
    failed    = await _count(RemediationStatus.FAILED)
    rolled_back = await _count(RemediationStatus.ROLLED_BACK)
    timed_out = await _count(RemediationStatus.TIMED_OUT)

    # Total all-time
    total_r   = await db.execute(select(func.count(RemediationAction.id)))
    total     = total_r.scalar_one() or 0

    # Active playbooks
    pb_r   = await db.execute(
        select(func.count(RemediationPlaybook.id)).where(RemediationPlaybook.is_active == True)  # noqa: E712
    )
    active_playbooks = pb_r.scalar_one() or 0

    return {
        "pending_approval":  pending,
        "executing":         executing,
        "completed_today":   completed_today,
        "failed":            failed,
        "rolled_back":       rolled_back,
        "timed_out":         timed_out,
        "total":             total,
        "active_playbooks":  active_playbooks,
    }
