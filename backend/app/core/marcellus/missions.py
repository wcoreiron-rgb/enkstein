from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.scanner import scan_text
from app.core.database import AsyncSessionLocal
from app.core.marcellus.crypto import decrypt_json, encrypt_json
from app.core.marcellus.mission_schemas import (
    CortexMissionCreate,
    CortexMissionObservationRead,
    CortexMissionObservationReview,
    CortexMissionRead,
    CortexMissionRunRead,
    CortexMissionUpdate,
    CortexOvernightBriefRead,
)
from app.core.marcellus.runtime_security import require_approver
from app.core.swarm.orchestrator import create_swarm_job, run_swarm_job
from app.core.swarm.schemas import SwarmJobCreate
from app.models.marcellus import (
    CortexMission,
    CortexMissionObservation,
    CortexOvernightBrief,
    ReflexExecution,
)
from app.models.swarm import SwarmJob
from app.trust_fabric import ActionRequest, enforce
from app.trust_fabric.agt_bridge import audit_prompt


_CADENCE = {
    "manual": None,
    "hourly": timedelta(hours=1),
    "every_6h": timedelta(hours=6),
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
}
_ADMIN_ROLES = {"admin", "security_admin", "super_admin"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _next_run(cadence: str, *, now: datetime | None = None) -> datetime | None:
    delta = _CADENCE.get(cadence)
    return ((now or _now()) + delta) if delta else None


def _owner_allowed(user: dict[str, Any], owner_id: str) -> bool:
    claimed = str(user.get("sub") or user.get("id") or "")
    return claimed == owner_id or str(user.get("role", "")).lower() in _ADMIN_ROLES


def _require_owner(user: dict[str, Any], owner_id: str) -> None:
    if not _owner_allowed(user, owner_id):
        raise HTTPException(status_code=403, detail="Mission owner access required")


def _mission_objective(mission: CortexMission) -> str:
    return str(decrypt_json(mission.objective_ciphertext, mission.objective_digest)["objective"])


def _mission_read(mission: CortexMission) -> CortexMissionRead:
    return CortexMissionRead(
        id=mission.id,
        tenant_id=mission.tenant_id,
        owner_id=mission.owner_id,
        name=mission.name,
        objective=_mission_objective(mission),
        status=mission.status,
        cadence=mission.cadence,
        autonomy_mode=mission.autonomy_mode,
        profile=mission.profile,
        classification=mission.classification,
        participants=json.loads(mission.participants_json or "[]"),
        parallelism=mission.parallelism,
        model_profile=mission.model_profile,
        run_count=mission.run_count,
        latest_job_id=mission.latest_job_id,
        latest_status=mission.latest_status,
        last_run_at=mission.last_run_at,
        next_run_at=mission.next_run_at,
        created_at=mission.created_at,
        updated_at=mission.updated_at,
    )


def _observation_read(observation: CortexMissionObservation) -> CortexMissionObservationRead:
    summary = decrypt_json(observation.summary_ciphertext, observation.summary_digest)["summary"]
    return CortexMissionObservationRead(
        id=observation.id,
        mission_id=observation.mission_id,
        job_id=observation.job_id,
        status=observation.status,
        severity=observation.severity,
        summary=summary,
        evidence=json.loads(observation.evidence_json or "{}"),
        proposed_by=observation.proposed_by,
        reviewed_by=observation.reviewed_by,
        review_reason=observation.review_reason,
        created_at=observation.created_at,
        reviewed_at=observation.reviewed_at,
    )


async def _policy(
    db: AsyncSession,
    *,
    action: str,
    tenant_id: str,
    actor_id: str,
    actor_name: str,
    actor_type: str,
    target: str,
    context: dict[str, Any],
):
    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_missions",
            actor_id=actor_id,
            actor_name=actor_name,
            actor_type=actor_type,
            action=action,
            target=target,
            target_type="cortex_mission",
            context={"tenant_id": tenant_id, **context},
        ),
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Trust Fabric denied the Mission action")
    return decision


async def create_mission(
    db: AsyncSession,
    payload: CortexMissionCreate,
    *,
    owner_id: str,
    owner_name: str,
) -> CortexMissionRead:
    await _policy(
        db,
        action="mission_create",
        tenant_id=payload.tenant_id,
        actor_id=owner_id,
        actor_name=owner_name,
        actor_type="user",
        target=payload.name,
        context={
            "classification": payload.classification,
            "autonomy_mode": payload.autonomy_mode,
            "cadence": payload.cadence,
            "participants": payload.participants,
        },
    )
    objective_ciphertext, objective_digest = encrypt_json({"objective": payload.objective})
    mission = CortexMission(
        tenant_id=payload.tenant_id,
        owner_id=owner_id,
        name=payload.name,
        objective_ciphertext=objective_ciphertext,
        objective_digest=objective_digest,
        cadence=payload.cadence,
        autonomy_mode=payload.autonomy_mode,
        profile=payload.profile,
        classification=payload.classification,
        participants_json=json.dumps(payload.participants),
        parallelism=payload.parallelism,
        model_profile=payload.model_profile,
        next_run_at=_next_run(payload.cadence),
    )
    db.add(mission)
    await db.commit()
    await db.refresh(mission)
    return _mission_read(mission)


async def list_missions(db: AsyncSession, tenant_id: str, *, user: dict[str, Any], owner_id: str) -> list[CortexMissionRead]:
    query = select(CortexMission).where(CortexMission.tenant_id == tenant_id)
    if str(user.get("role", "")).lower() not in _ADMIN_ROLES:
        query = query.where(CortexMission.owner_id == owner_id)
    result = await db.execute(query.order_by(CortexMission.status, CortexMission.next_run_at.asc().nullslast()))
    return [_mission_read(item) for item in result.scalars().all()]


async def _get_mission(db: AsyncSession, tenant_id: str, mission_id: UUID) -> CortexMission:
    result = await db.execute(
        select(CortexMission).where(CortexMission.tenant_id == tenant_id, CortexMission.id == mission_id)
    )
    mission = result.scalar_one_or_none()
    if mission is None:
        raise HTTPException(status_code=404, detail="Mission not found")
    return mission


async def update_mission(
    db: AsyncSession,
    tenant_id: str,
    mission_id: UUID,
    payload: CortexMissionUpdate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
) -> CortexMissionRead:
    mission = await _get_mission(db, tenant_id, mission_id)
    _require_owner(user, mission.owner_id)
    await _policy(
        db,
        action="mission_update",
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        actor_type="user",
        target=str(mission.id),
        context={"updates": sorted(payload.model_dump(exclude_none=True, exclude={"tenant_id"}))},
    )
    if payload.status is not None:
        mission.status = payload.status
    if payload.cadence is not None:
        mission.cadence = payload.cadence
        mission.next_run_at = _next_run(payload.cadence)
    if payload.autonomy_mode is not None:
        mission.autonomy_mode = payload.autonomy_mode
    if mission.status != "active":
        mission.next_run_at = None
    elif mission.next_run_at is None:
        mission.next_run_at = _next_run(mission.cadence)
    mission.updated_at = _now()
    await db.commit()
    await db.refresh(mission)
    return _mission_read(mission)


async def launch_mission(
    db: AsyncSession,
    mission: CortexMission,
    *,
    actor_id: str,
    actor_name: str,
    actor_type: str = "user",
) -> CortexMissionRunRead:
    if mission.status != "active":
        raise HTTPException(status_code=409, detail="Only active Missions can run")
    await _policy(
        db,
        action="mission_run",
        tenant_id=mission.tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        actor_type=actor_type,
        target=str(mission.id),
        context={
            "classification": mission.classification,
            "autonomy_mode": mission.autonomy_mode,
            "allowed_actions": ["read", "analyze", "recommend"],
        },
    )
    participants = json.loads(mission.participants_json or "[]")
    job = await create_swarm_job(
        db,
        SwarmJobCreate(
            name=f"Mission: {mission.name}",
            profile=mission.profile,
            requested_by=mission.owner_id,
            trigger_type="mission",
            classification=mission.classification,
            participants=participants,
            task_type="mission_observe",
            input={
                "source": "marcellus_mission",
                "mission_id": str(mission.id),
                "tenant_id": mission.tenant_id,
                "objective_digest": mission.objective_digest,
                "autonomy_mode": mission.autonomy_mode,
                "allowed_actions": ["read", "analyze", "recommend"],
            },
            parallelism=mission.parallelism,
            model_profile=mission.model_profile,
        ),
    )
    now = _now()
    mission.latest_job_id = job.id
    mission.latest_status = job.status.value
    mission.last_run_at = now
    mission.next_run_at = _next_run(mission.cadence, now=now)
    mission.run_count += 1
    mission.updated_at = now
    await db.commit()
    return CortexMissionRunRead(
        mission_id=mission.id,
        job_id=job.id,
        status=job.status.value,
        message="Mission Swarm queued with read/analyze/recommend authority",
    )


async def run_mission_job(mission_id: UUID, job_id: UUID) -> None:
    await run_swarm_job(job_id)
    async with AsyncSessionLocal() as db:
        mission_result = await db.execute(select(CortexMission).where(CortexMission.id == mission_id))
        mission = mission_result.scalar_one_or_none()
        job = await db.get(SwarmJob, job_id)
        if mission is None or job is None:
            return
        mission.latest_status = job.status.value
        mission.updated_at = _now()
        existing = await db.execute(
            select(CortexMissionObservation).where(
                CortexMissionObservation.tenant_id == mission.tenant_id,
                CortexMissionObservation.mission_id == mission.id,
                CortexMissionObservation.job_id == job.id,
            )
        )
        if existing.scalar_one_or_none() is not None:
            await db.commit()
            return
        summary = job.final_summary or job.error_message or f"Mission run finished with status {job.status.value}."
        source_scan = scan_text(summary, redact=True)
        source_audit = audit_prompt(summary)
        safe = not (source_audit.is_injection_risk and source_audit.risk_score >= 50)
        rendered = (source_scan.redacted if source_scan.is_sensitive else summary)[:4000] if safe else "Mission observation blocked by memory safety policy."
        try:
            decision = await _policy(
                db,
                action="mission_memory_propose",
                tenant_id=mission.tenant_id,
                actor_id="mission-runtime",
                actor_name="Enkstein Mission Runtime",
                actor_type="agent",
                target=str(mission.id),
                context={"job_id": str(job.id), "severity": job.overall_severity or "low", "safe": safe},
            )
            observation_status = "proposed" if safe and decision.allowed else "blocked"
        except HTTPException:
            observation_status = "blocked"
        ciphertext, digest = encrypt_json({"summary": rendered})
        observation = CortexMissionObservation(
            tenant_id=mission.tenant_id,
            mission_id=mission.id,
            job_id=job.id,
            status=observation_status,
            severity=job.overall_severity or ("high" if job.status.value == "failed" else "low"),
            summary_ciphertext=ciphertext,
            summary_digest=digest,
            evidence_json=json.dumps(
                {
                    "job_id": str(job.id),
                    "job_status": job.status.value,
                    "confidence": job.confidence,
                    "participants": json.loads(job.participants_json or "[]"),
                    "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                },
                separators=(",", ":"),
            ),
        )
        db.add(observation)
        await db.commit()


async def list_observations(
    db: AsyncSession,
    tenant_id: str,
    *,
    user: dict[str, Any],
    owner_id: str,
    status_filter: str | None = None,
    limit: int = 100,
) -> list[CortexMissionObservationRead]:
    query = (
        select(CortexMissionObservation)
        .join(CortexMission, CortexMission.id == CortexMissionObservation.mission_id)
        .where(CortexMissionObservation.tenant_id == tenant_id)
    )
    if str(user.get("role", "")).lower() not in _ADMIN_ROLES:
        query = query.where(CortexMission.owner_id == owner_id)
    if status_filter:
        query = query.where(CortexMissionObservation.status == status_filter)
    result = await db.execute(query.order_by(desc(CortexMissionObservation.created_at)).limit(limit))
    return [_observation_read(item) for item in result.scalars().all()]


async def review_observation(
    db: AsyncSession,
    tenant_id: str,
    observation_id: UUID,
    payload: CortexMissionObservationReview,
    *,
    user: dict[str, Any],
    actor_name: str,
) -> CortexMissionObservationRead:
    result = await db.execute(
        select(CortexMissionObservation, CortexMission)
        .join(CortexMission, CortexMission.id == CortexMissionObservation.mission_id)
        .where(
            CortexMissionObservation.tenant_id == tenant_id,
            CortexMissionObservation.id == observation_id,
        )
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Mission memory proposal not found")
    observation, mission = row
    _require_owner(user, mission.owner_id)
    if observation.status != "proposed":
        raise HTTPException(status_code=409, detail=f"Mission memory is already {observation.status}")
    approver = require_approver(user, observation.proposed_by)
    await _policy(
        db,
        action=f"mission_memory_{payload.decision}",
        tenant_id=tenant_id,
        actor_id=approver,
        actor_name=actor_name,
        actor_type="user",
        target=str(observation.id),
        context={"mission_id": str(mission.id)},
    )
    observation.status = "approved" if payload.decision == "approve" else "rejected"
    observation.reviewed_by = approver
    observation.review_reason = payload.reason
    observation.reviewed_at = _now()
    await db.commit()
    await db.refresh(observation)
    return _observation_read(observation)


async def generate_overnight_brief(
    db: AsyncSession,
    tenant_id: str,
    *,
    user: dict[str, Any],
    owner_id: str,
    hours: int = 12,
) -> CortexOvernightBriefRead:
    end = _now()
    start = end - timedelta(hours=hours)
    missions_query = select(CortexMission).where(CortexMission.tenant_id == tenant_id)
    if str(user.get("role", "")).lower() not in _ADMIN_ROLES:
        missions_query = missions_query.where(CortexMission.owner_id == owner_id)
    missions = list((await db.execute(missions_query)).scalars().all())
    mission_ids = [item.id for item in missions]
    observations: list[CortexMissionObservation] = []
    if mission_ids:
        observations = list(
            (
                await db.execute(
                    select(CortexMissionObservation)
                    .where(
                        CortexMissionObservation.tenant_id == tenant_id,
                        CortexMissionObservation.mission_id.in_(mission_ids),
                        CortexMissionObservation.created_at >= start,
                    )
                    .order_by(desc(CortexMissionObservation.created_at))
                )
            ).scalars().all()
        )
    proposed = [item for item in observations if item.status == "proposed"]
    approved = [item for item in observations if item.status == "approved"]
    material = [
        {
            "observation_id": str(item.id),
            "mission_id": str(item.mission_id),
            "severity": item.severity,
            "status": item.status,
            "summary": decrypt_json(item.summary_ciphertext, item.summary_digest)["summary"],
            "evidence": json.loads(item.evidence_json or "{}"),
            "observed_at": item.created_at.isoformat(),
        }
        for item in observations[:20]
        if item.status in {"approved", "proposed"}
    ]
    decisions = [
        {
            "type": "mission_memory_review",
            "observation_id": str(item.id),
            "mission_id": str(item.mission_id),
            "severity": item.severity,
            "summary": decrypt_json(item.summary_ciphertext, item.summary_digest)["summary"],
        }
        for item in proposed[:20]
    ]
    active = [item for item in missions if item.status == "active"]
    running_arms = sorted(
        {
            participant
            for mission in active
            if mission.latest_status in {"pending", "running"}
            for participant in json.loads(mission.participants_json or "[]")
        }
    )
    reflexes = list(
        (
            await db.execute(
                select(ReflexExecution)
                .where(ReflexExecution.tenant_id == tenant_id, ReflexExecution.created_at >= start)
                .order_by(desc(ReflexExecution.created_at))
                .limit(20)
            )
        ).scalars().all()
    )
    last_approved = max((item.created_at for item in approved), default=None)
    health_status = "unconfigured" if not missions else "healthy" if last_approved and last_approved >= start else "warming"
    blocked = [
        {"mission_id": str(item.id), "name": item.name, "status": item.latest_status}
        for item in missions
        if item.latest_status in {"blocked", "failed"}
    ]
    blocked.extend(
        {"observation_id": str(item.id), "mission_id": str(item.mission_id), "status": item.status}
        for item in observations
        if item.status == "blocked"
    )
    payload = {
        "headline": (
            f"{len(material)} material change{'s' if len(material) != 1 else ''}; "
            f"{len(decisions)} decision{'s' if len(decisions) != 1 else ''} awaiting review."
        ),
        "active_missions": [
            {
                "id": str(item.id),
                "name": item.name,
                "status": item.status,
                "latest_status": item.latest_status,
                "next_run_at": item.next_run_at.isoformat() if item.next_run_at else None,
            }
            for item in active
        ],
        "material_changes": material,
        "decisions_needed": decisions,
        "running_arms": running_arms,
        "recent_reflex_actions": [
            {
                "id": str(item.id),
                "event_type": item.event_type,
                "status": item.status,
                "policy_outcome": item.policy_outcome,
                "created_at": item.created_at.isoformat(),
            }
            for item in reflexes
        ],
        "blocked_actions": blocked[:20],
        "security_twin_health": {
            "status": health_status,
            "active_missions": len(active),
            "approved_observations": len(approved),
            "pending_memory_reviews": len(proposed),
            "last_approved_observation_at": last_approved.isoformat() if last_approved else None,
        },
    }
    ciphertext, digest = encrypt_json({"payload": payload})
    brief = CortexOvernightBrief(
        tenant_id=tenant_id,
        owner_id=owner_id,
        window_start=start,
        window_end=end,
        payload_ciphertext=ciphertext,
        payload_digest=digest,
    )
    db.add(brief)
    await db.commit()
    await db.refresh(brief)
    return CortexOvernightBriefRead(
        id=brief.id,
        generated_at=brief.created_at,
        window_start=start,
        window_end=end,
        **payload,
    )


async def mission_scheduler_loop(session_factory) -> None:
    while True:
        await asyncio.sleep(60)
        now = _now()
        runs: list[tuple[UUID, UUID]] = []
        try:
            async with session_factory() as db:
                result = await db.execute(
                    select(CortexMission)
                    .where(
                        CortexMission.status == "active",
                        CortexMission.next_run_at.is_not(None),
                        CortexMission.next_run_at <= now,
                    )
                    .order_by(CortexMission.next_run_at)
                    .limit(10)
                    .with_for_update(skip_locked=True)
                )
                for mission in result.scalars().all():
                    try:
                        launched = await launch_mission(
                            db,
                            mission,
                            actor_id="mission-scheduler",
                            actor_name="Enkstein Mission Scheduler",
                            actor_type="agent",
                        )
                        runs.append((mission.id, launched.job_id))
                    except HTTPException:
                        mission.latest_status = "blocked"
                        mission.next_run_at = _next_run(mission.cadence, now=now)
                        await db.commit()
            if runs:
                await asyncio.gather(*(run_mission_job(mission_id, job_id) for mission_id, job_id in runs))
        except asyncio.CancelledError:
            raise
        except Exception:
            # The scheduler never logs Mission payloads or summaries.
            continue
