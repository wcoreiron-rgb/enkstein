from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal, get_db
from app.core.deps import get_current_user
from app.core.tenancy import assert_tenant_visible, caller_tenant
from app.core.swarm.orchestrator import create_swarm_job, run_swarm_job, run_swarm_job_in_session
from app.core.swarm.schemas import SwarmActionResponse, SwarmJobCreate, SwarmJobRead, SwarmTaskRead
from app.models.swarm import SwarmJob, SwarmJobStatus, SwarmTask, SwarmTaskStatus

router = APIRouter(prefix="/swarm/jobs", tags=["Swarm"])
_TERMINAL_JOB_STATUSES = {
    SwarmJobStatus.COMPLETED,
    SwarmJobStatus.FAILED,
    SwarmJobStatus.CANCELLED,
    SwarmJobStatus.BLOCKED,
    SwarmJobStatus.REQUIRES_APPROVAL,
}


def _sse(event_type: str, payload: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"


async def _scoped_job(job_id: str, db: AsyncSession, user: dict) -> SwarmJob:
    try:
        job_uuid = UUID(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Swarm job not found") from exc
    result = await db.execute(select(SwarmJob).where(SwarmJob.id == job_uuid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Swarm job not found")
    assert_tenant_visible(user, job.tenant_id)
    return job


def _task_status_events(
    prev: dict[str, str],
    tasks: list[SwarmTask],
) -> tuple[list[tuple[str, dict]], dict[str, str]]:
    events: list[tuple[str, dict]] = []
    current: dict[str, str] = {}
    for task in tasks:
        task_id = str(task.id)
        status = task.status.value
        current[task_id] = status
        if prev.get(task_id) == status:
            continue
        payload = {
            "task_id": task_id,
            "claw": task.claw,
            "status": status,
            "severity": task.severity,
            "risk_score": task.risk_score,
        }
        parsed_output: dict | None = None
        if task.output_json:
            try:
                maybe = json.loads(task.output_json)
                if isinstance(maybe, dict):
                    parsed_output = maybe
            except Exception:
                parsed_output = None

        if parsed_output:
            if parsed_output.get("execution_mode"):
                payload["execution_mode"] = parsed_output.get("execution_mode")
            if parsed_output.get("fallback_reason"):
                payload["fallback_reason"] = parsed_output.get("fallback_reason")
        if status == SwarmTaskStatus.RUNNING.value:
            events.append(("task_started", payload))
        elif status == SwarmTaskStatus.COMPLETED.value:
            events.append(("task_completed", payload))
        elif status in {SwarmTaskStatus.FAILED.value, SwarmTaskStatus.BLOCKED.value, SwarmTaskStatus.CANCELLED.value}:
            events.append(("task_status_changed", payload))
    return events, current


@router.post("/presets/suspicious-identity", response_model=SwarmJobRead, status_code=201)
async def create_suspicious_identity_preset(
    body: dict | None = None,
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Sprint 6 preset: Suspicious Identity Investigation Swarm.
    Launches a cross-pillar investigation with governance-friendly defaults.
    """
    payload = body or {}
    identity = payload.get("identity") or payload.get("user_id") or payload.get("principal") or "unknown_identity"
    time_range = payload.get("time_range") or "24h"
    source = payload.get("source") or "manual_preset"
    classification = payload.get("classification") or "confidential"

    swarm_payload = SwarmJobCreate(
        name=payload.get("name") or f"Suspicious Identity Investigation — {identity}",
        profile="INCIDENT_RESPONSE",
        requested_by=payload.get("requested_by") or "portal-user",
        trigger_type=payload.get("trigger_type") or "manual_preset",
        classification=classification,
        participants=[
            "identityclaw",
            "threatclaw",
            "cloudclaw",
            "dataclaw",
            "complianceclaw",
            "automationclaw",
        ],
        task_type="investigate_identity_risk",
        input={
            "identity": identity,
            "time_range": time_range,
            "source": source,
            "scenario": "suspicious_identity_investigation",
            "requested_outcome": "risk_timeline_blast_radius_and_actions",
        },
        parallelism=6,
        model_profile=payload.get("model_profile") or "swarm_judge_profile",
    )
    job = await create_swarm_job(db, swarm_payload, tenant_id=caller_tenant(user))
    if payload.get("requires_approval_for_actions", True):
        job.status = SwarmJobStatus.REQUIRES_APPROVAL
        job.final_summary = "Awaiting approval before suspicious identity swarm execution"
        await db.commit()
        await db.refresh(job)
    elif os.getenv("PYTEST_CURRENT_TEST") or background_tasks is None:
        await run_swarm_job_in_session(db, job.id)
        await db.refresh(job)
    else:
        background_tasks.add_task(run_swarm_job, job.id)
    return job


@router.post("/presets/microsoft-identity-incident", response_model=SwarmJobRead, status_code=201)
async def create_microsoft_identity_incident_preset(
    body: dict | None = None,
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Microsoft security demo preset: identity-led incident investigation.
    Uses Entra/Defender/Sentinel/Azure-capable Capability Nodes when connectors are configured,
    with deterministic fallback preserved for local demos without credentials.
    """
    payload = body or {}
    identity = payload.get("identity") or payload.get("user_id") or payload.get("principal") or "unknown_identity"
    time_range = payload.get("time_range") or "24h"
    classification = payload.get("classification") or "confidential"

    swarm_payload = SwarmJobCreate(
        name=payload.get("name") or f"Microsoft Identity Incident - {identity}",
        profile="INCIDENT_RESPONSE",
        requested_by=payload.get("requested_by") or "portal-user",
        trigger_type=payload.get("trigger_type") or "manual_preset",
        classification=classification,
        participants=[
            "identityclaw",
            "cloudclaw",
            "endpointclaw",
            "logclaw",
            "threatclaw",
            "complianceclaw",
            "automationclaw",
        ],
        task_type="investigate_microsoft_identity_incident",
        input={
            "identity": identity,
            "time_range": time_range,
            "scenario": "microsoft_identity_incident",
            "preferred_connectors": [
                "entra_id",
                "azure_defender",
                "defender_endpoint",
                "microsoft_sentinel",
            ],
            "requested_outcome": "identity_endpoint_cloud_log_correlation_ticket_draft",
        },
        parallelism=7,
        model_profile=payload.get("model_profile") or "swarm_judge_profile",
    )
    job = await create_swarm_job(db, swarm_payload, tenant_id=caller_tenant(user))
    if payload.get("requires_approval_for_actions", True):
        job.status = SwarmJobStatus.REQUIRES_APPROVAL
        job.final_summary = "Awaiting approval before Microsoft identity incident swarm execution"
        await db.commit()
        await db.refresh(job)
    elif os.getenv("PYTEST_CURRENT_TEST") or background_tasks is None:
        await run_swarm_job_in_session(db, job.id)
        await db.refresh(job)
    else:
        background_tasks.add_task(run_swarm_job, job.id)
    return job


@router.post("", response_model=SwarmJobRead, status_code=201)
async def create_job(
    payload: SwarmJobCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    job = await create_swarm_job(db, payload, tenant_id=caller_tenant(user))
    # Tests use an isolated in-memory DB session. Running inline avoids spawning
    # a separate session that cannot see test tables.
    if os.getenv("PYTEST_CURRENT_TEST"):
        await run_swarm_job_in_session(db, job.id)
    else:
        background_tasks.add_task(run_swarm_job, job.id)
    return job


@router.get("", response_model=list[SwarmJobRead])
async def list_jobs(
    status: Optional[SwarmJobStatus] = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    q = select(SwarmJob).order_by(desc(SwarmJob.created_at)).limit(limit)
    if status:
        q = q.where(SwarmJob.status == status)
    scope = caller_tenant(user)
    if scope is not None:
        q = q.where(SwarmJob.tenant_id == scope)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{job_id}", response_model=SwarmJobRead)
async def get_job(job_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    return await _scoped_job(job_id, db, user)


@router.get("/{job_id}/tasks", response_model=list[SwarmTaskRead])
async def get_job_tasks(job_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    job = await _scoped_job(job_id, db, user)
    result = await db.execute(
        select(SwarmTask)
        .where(SwarmTask.swarm_job_id == job.id)
        .order_by(SwarmTask.created_at.asc())
    )
    return result.scalars().all()


@router.get("/{job_id}/stream", summary="Live swarm job events stream (SSE)")
async def stream_job_events(
    job_id: str,
    timeout_seconds: int = Query(default=30, ge=2, le=600),
    poll_interval_ms: int = Query(default=500, ge=200, le=5000),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    job_uuid = UUID(job_id)
    # Authorize before starting a long-lived stream; every subsequent poll is
    # constrained by this immutable job id.
    await _scoped_job(job_id, db, user)

    async def event_gen():
        start = time.monotonic()
        prev_task_status: dict[str, str] = {}
        sent_job_started = False

        while True:
            # Tests run against an in-memory DB dependency; production uses a fresh
            # session per poll so long-lived streams don't pin request sessions.
            if os.getenv("PYTEST_CURRENT_TEST"):
                loop_db = db
                close_loop_db = False
            else:
                loop_db = AsyncSessionLocal()
                close_loop_db = True

            try:
                result = await loop_db.execute(select(SwarmJob).where(SwarmJob.id == job_uuid))
                job = result.scalar_one_or_none()
                if not job:
                    yield _sse("error", {"message": "Swarm job not found", "job_id": job_id})
                    return

                task_result = await loop_db.execute(
                    select(SwarmTask)
                    .where(SwarmTask.swarm_job_id == job_uuid)
                    .order_by(SwarmTask.created_at.asc())
                )
                tasks = task_result.scalars().all()

                yield _sse(
                    "job_snapshot",
                    {
                        "job_id": job_id,
                        "status": job.status.value,
                        "overall_severity": job.overall_severity,
                        "confidence": job.confidence,
                        "task_count": len(tasks),
                    },
                )

                if job.status == SwarmJobStatus.RUNNING and not sent_job_started:
                    sent_job_started = True
                    yield _sse("job_started", {"job_id": job_id})

                status_events, prev_task_status = _task_status_events(prev_task_status, tasks)
                for event_name, payload in status_events:
                    yield _sse(event_name, payload)

                if job.status in _TERMINAL_JOB_STATUSES:
                    yield _sse(
                        "job_completed",
                        {
                            "job_id": job_id,
                            "status": job.status.value,
                            "overall_severity": job.overall_severity,
                            "confidence": job.confidence,
                            "summary": job.final_summary,
                        },
                    )
                    return
            finally:
                if close_loop_db:
                    await loop_db.close()

            if (time.monotonic() - start) >= timeout_seconds:
                yield _sse("stream_timeout", {"job_id": job_id, "timeout_seconds": timeout_seconds})
                return
            await asyncio.sleep(poll_interval_ms / 1000.0)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@router.post("/{job_id}/cancel", response_model=SwarmActionResponse)
async def cancel_job(job_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    job = await _scoped_job(job_id, db, user)
    if job.status in {SwarmJobStatus.COMPLETED, SwarmJobStatus.FAILED, SwarmJobStatus.CANCELLED}:
        return SwarmActionResponse(job_id=job.id, status=job.status, message="Job already finalized")

    job.status = SwarmJobStatus.CANCELLED
    task_result = await db.execute(select(SwarmTask).where(SwarmTask.swarm_job_id == job.id))
    for task in task_result.scalars().all():
        if task.status in {SwarmTaskStatus.PENDING, SwarmTaskStatus.RUNNING}:
            task.status = SwarmTaskStatus.CANCELLED
    await db.commit()
    return SwarmActionResponse(job_id=job.id, status=job.status, message="Job cancelled")


@router.post("/{job_id}/approve", response_model=SwarmActionResponse)
async def approve_job(job_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    job = await _scoped_job(job_id, db, user)
    if job.status != SwarmJobStatus.REQUIRES_APPROVAL:
        return SwarmActionResponse(job_id=job.id, status=job.status, message="No approval required")
    # Pre-execution approval gate: run the job now.
    if not job.started_at:
        job.status = SwarmJobStatus.PENDING
        await db.commit()
        await run_swarm_job_in_session(db, job.id)
        await db.refresh(job)
        return SwarmActionResponse(
            job_id=job.id,
            status=job.status,
            message="Job approved and executed",
        )

    # Post-judge approval gate: finalize as completed.
    job.status = SwarmJobStatus.COMPLETED
    await db.commit()
    return SwarmActionResponse(job_id=job.id, status=job.status, message="Job approved")
