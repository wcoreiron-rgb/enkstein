"""
Enkstein — Autonomy Mode Controls API
Platform-level and per-agent autonomy settings.

GET  /autonomy/settings              — get platform settings
PATCH /autonomy/settings             — update platform ceiling / flags
POST /autonomy/emergency/activate    — activate emergency mode
POST /autonomy/emergency/deactivate  — deactivate emergency mode
GET  /autonomy/agents                — list agents with their effective mode
PATCH /autonomy/agents/{id}/mode     — update a single agent's autonomy mode
"""
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from pydantic import BaseModel

from app.core.database import get_db
from app.models.agent import Agent, PlatformSettings, ExecutionMode
from app.services.agent_runner import _apply_autonomy_ceiling

router = APIRouter(prefix="/autonomy", tags=["CoreOS — Autonomy Controls"])


class EmergencyActivateRequest(BaseModel):
    reason: str
    activated_by: str = "platform_admin"


class EmergencyDeactivateRequest(BaseModel):
    deactivated_by: str = "platform_admin"

# ─── Mode metadata for the API ────────────────────────────────────────────────

MODE_INFO = {
    ExecutionMode.MONITOR: {
        "label": "Monitor",
        "description": "Observe and log only. Zero writes, zero actions. Full visibility, zero blast radius.",
        "color": "blue",
        "risk": "none",
    },
    ExecutionMode.ASSIST: {
        "label": "Assist",
        "description": "Surface findings and suggested actions for human review. Nothing executes until approved.",
        "color": "cyan",
        "risk": "low",
    },
    ExecutionMode.APPROVAL: {
        "label": "Approval",
        "description": "Prepare a full action plan, then pause. Every action requires explicit human approval before any write.",
        "color": "purple",
        "risk": "low",
    },
    ExecutionMode.AUTONOMOUS: {
        "label": "Autonomous",
        "description": "Auto-execute pre-approved low/medium risk actions. High/critical actions held for approval.",
        "color": "green",
        "risk": "medium",
    },
    ExecutionMode.EMERGENCY: {
        "label": "Emergency",
        "description": "Containment-only mode. Only pre-approved actions (isolate, block, quarantine) are executed. Everything else blocked.",
        "color": "red",
        "risk": "controlled",
    },
}


async def _get_or_create_settings(db: AsyncSession) -> PlatformSettings:
    result = await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    settings = result.scalar_one_or_none()
    if not settings:
        settings = PlatformSettings(id=1)
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    return settings


# ─── Platform settings ────────────────────────────────────────────────────────

@router.get("/settings")
async def get_platform_settings(db: AsyncSession = Depends(get_db)):
    settings = await _get_or_create_settings(db)
    return {
        "autonomy_ceiling":              settings.autonomy_ceiling,
        "emergency_mode_active":         settings.emergency_mode_active,
        "emergency_mode_reason":         settings.emergency_mode_reason,
        "emergency_mode_activated_at":   settings.emergency_mode_activated_at,
        "emergency_mode_activated_by":   settings.emergency_mode_activated_by,
        "change_window_active":          settings.change_window_active,
        "change_window_reason":          settings.change_window_reason,
        "require_mfa_for_approval":      settings.require_mfa_for_approval,
        "auto_approve_low_risk":         settings.auto_approve_low_risk,
        "max_concurrent_runs":           settings.max_concurrent_runs,
        "updated_at":                    settings.updated_at,
        "mode_info":                     {k: v for k, v in MODE_INFO.items()},
    }


@router.patch("/settings")
async def update_platform_settings(
    autonomy_ceiling:         Optional[str]  = Body(None),
    change_window_active:     Optional[bool] = Body(None),
    change_window_reason:     Optional[str]  = Body(None),
    require_mfa_for_approval: Optional[bool] = Body(None),
    auto_approve_low_risk:    Optional[bool] = Body(None),
    max_concurrent_runs:      Optional[int]  = Body(None),
    updated_by:               Optional[str]  = Body(None),
    db: AsyncSession = Depends(get_db),
):
    settings = await _get_or_create_settings(db)

    if autonomy_ceiling is not None:
        if autonomy_ceiling not in [m.value for m in ExecutionMode]:
            raise HTTPException(status_code=400, detail=f"Invalid mode: {autonomy_ceiling}")
        settings.autonomy_ceiling = autonomy_ceiling
    if change_window_active is not None:
        settings.change_window_active = change_window_active
    if change_window_reason is not None:
        settings.change_window_reason = change_window_reason
    if require_mfa_for_approval is not None:
        settings.require_mfa_for_approval = require_mfa_for_approval
    if auto_approve_low_risk is not None:
        settings.auto_approve_low_risk = auto_approve_low_risk
    if max_concurrent_runs is not None:
        settings.max_concurrent_runs = max_concurrent_runs
    if updated_by is not None:
        settings.updated_by = updated_by

    settings.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(settings)
    return {"status": "updated", "autonomy_ceiling": settings.autonomy_ceiling}


# ─── Emergency mode ───────────────────────────────────────────────────────────

@router.post("/emergency/activate")
async def activate_emergency_mode(
    payload: EmergencyActivateRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Activate emergency mode — forces ALL agents to EMERGENCY execution mode.
    Only pre-approved containment actions are allowed platform-wide.
    """
    settings = await _get_or_create_settings(db)
    reason = payload.reason
    activated_by = payload.activated_by
    settings.emergency_mode_active       = True
    settings.emergency_mode_reason       = reason
    settings.emergency_mode_activated_at = datetime.now(timezone.utc)
    settings.emergency_mode_activated_by = activated_by
    settings.updated_at                  = datetime.now(timezone.utc)
    settings.updated_by                  = activated_by
    await db.commit()

    return {
        "status":       "emergency_mode_activated",
        "reason":       reason,
        "activated_by": activated_by,
        "activated_at": settings.emergency_mode_activated_at,
        "effect":       "All agents forced to EMERGENCY mode — only containment actions allowed",
    }


@router.post("/emergency/deactivate")
async def deactivate_emergency_mode(
    payload: EmergencyDeactivateRequest,
    db: AsyncSession = Depends(get_db),
):
    settings = await _get_or_create_settings(db)
    deactivated_by = payload.deactivated_by
    prev_reason = settings.emergency_mode_reason
    settings.emergency_mode_active       = False
    settings.emergency_mode_reason       = None
    settings.emergency_mode_activated_at = None
    settings.emergency_mode_activated_by = None
    settings.updated_at                  = datetime.now(timezone.utc)
    settings.updated_by                  = deactivated_by
    await db.commit()

    return {
        "status":           "emergency_mode_deactivated",
        "previous_reason":  prev_reason,
        "deactivated_by":   deactivated_by,
        "ceiling_restored": settings.autonomy_ceiling,
    }


# ─── Per-agent mode management ────────────────────────────────────────────────

@router.get("/agents")
async def list_agent_modes(db: AsyncSession = Depends(get_db)):
    """List all agents with their configured mode and effective mode after ceiling."""
    settings = await _get_or_create_settings(db)
    result = await db.execute(select(Agent).where(Agent.status != "retired").order_by(Agent.claw, Agent.name))
    agents = result.scalars().all()

    return [
        {
            "id":              str(a.id),
            "name":            a.name,
            "claw":            a.claw,
            "configured_mode": a.execution_mode,
            "effective_mode":  _apply_autonomy_ceiling(a.execution_mode, settings),
            "risk_level":      a.risk_level,
            "status":          a.status,
            "requires_approval": a.requires_approval,
        }
        for a in agents
    ]


@router.patch("/agents/{agent_id}/mode")
async def update_agent_mode(
    agent_id: UUID,
    mode:       str = Body(...),
    updated_by: str = Body("platform_admin"),
    db: AsyncSession = Depends(get_db),
):
    if mode not in [m.value for m in ExecutionMode]:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    old_mode = agent.execution_mode
    agent.execution_mode = mode
    agent.updated_at = datetime.now(timezone.utc)
    await db.commit()

    settings = await _get_or_create_settings(db)
    effective = _apply_autonomy_ceiling(mode, settings)

    return {
        "agent_id":        str(agent_id),
        "agent_name":      agent.name,
        "old_mode":        old_mode,
        "configured_mode": mode,
        "effective_mode":  effective,
        "ceiling":         settings.autonomy_ceiling,
    }


@router.post("/agents/bulk-mode")
async def bulk_update_agent_modes(
    mode:        str        = Body(...),
    claw_filter: Optional[str] = Body(None),
    updated_by:  str        = Body("platform_admin"),
    db: AsyncSession = Depends(get_db),
):
    """Set all agents (optionally filtered by claw) to a specific mode."""
    if mode not in [m.value for m in ExecutionMode]:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {mode}")

    stmt = select(Agent).where(Agent.status != "retired")
    if claw_filter:
        stmt = stmt.where(Agent.claw == claw_filter)

    result = await db.execute(stmt)
    agents = result.scalars().all()

    for agent in agents:
        agent.execution_mode = mode
        agent.updated_at = datetime.now(timezone.utc)

    await db.commit()

    return {
        "status":  "updated",
        "mode":    mode,
        "count":   len(agents),
        "filter":  claw_filter or "all claws",
    }
