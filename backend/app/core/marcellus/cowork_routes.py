"""HTTP surface for durable Cowork jobs.

Every endpoint reads authoritative state from the database. The stream endpoint
is a *projection* of the durable event log rather than a live pipe into the
work, which is what lets a client disconnect, reload, or restart the desktop app
and pick the run back up exactly where it left off by replaying from
``after_sequence``.
"""

from __future__ import annotations

import asyncio
import json
import uuid

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.marcellus import cowork_jobs as jobs
from app.core.marcellus import cowork_states as states
from app.core.marcellus.ai_rate_limit import enforce_ai_rate_limit
from app.core.marcellus.cowork_browser import (
    acknowledge_browser_task,
    complete_browser_task,
    record_browser_progress,
)
from app.core.marcellus.cowork_runner import job_result, run_job
from app.core.marcellus.cowork_schemas import (
    CoworkBrowserAck,
    CoworkBrowserComplete,
    CoworkBrowserProgress,
    CoworkBrowserTaskRead,
    CoworkExecutorRead,
    CoworkExecutorStatusRead,
    CoworkJobCreate,
    CoworkJobEventRead,
    CoworkJobRead,
    CoworkJobResultRead,
    CoworkJobStepRead,
    CoworkResumeRequest,
    CoworkRetryRequest,
)
from app.core.marcellus.cowork_executors import (
    EXECUTOR_LABELS,
    availability_report,
    resolve_executor,
)
from app.core.marcellus.native_workspace import get_binding
from app.core.marcellus.runtime_security import actor_id, resolve_tenant
from app.models.marcellus import CoworkBrowserTask, CoworkJob

from sqlalchemy import func, select


router = APIRouter(prefix="/marcellus/cowork", tags=["Enkstein Cowork Jobs"])


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(jsonable_encoder(payload), separators=(',', ':'))}\n\n"


async def _browser_task_read(db: AsyncSession, job: CoworkJob) -> CoworkBrowserTaskRead | None:
    result = await db.execute(
        select(CoworkBrowserTask)
        .where(CoworkBrowserTask.job_id == job.id)
        .order_by(CoworkBrowserTask.created_at.desc())
        .limit(1)
    )
    task = result.scalar_one_or_none()
    if task is None:
        return None
    try:
        attachments = json.loads(task.attachments_json or "[]")
    except json.JSONDecodeError:
        attachments = []
    return CoworkBrowserTaskRead(
        id=task.id,
        provider=task.provider,
        state=task.state,
        provider_tab_id=task.provider_tab_id,
        provider_conversation_id=task.provider_conversation_id,
        heartbeat_at=task.heartbeat_at,
        chunk_count=task.chunk_count,
        truncated=task.truncated,
        attachments=attachments if isinstance(attachments, list) else [],
        failure_reason=task.failure_reason,
        retry_token=task.retry_token,
        completed_at=task.completed_at,
    )


async def _job_read(db: AsyncSession, job: CoworkJob) -> CoworkJobRead:
    steps = await jobs.list_steps(db, job)
    latest = await db.execute(
        select(func.max(jobs.CoworkJobEvent.sequence)).where(jobs.CoworkJobEvent.job_id == job.id)
    )
    return CoworkJobRead(
        id=job.id,
        tenant_id=job.tenant_id,
        owner_id=job.owner_id,
        project_id=job.project_id,
        conversation_id=job.conversation_id,
        state=job.state,
        mode=job.mode,
        source=job.source,
        runtime_group=job.runtime_group,
        classification=job.classification,
        executor_preference=job.executor_preference,
        executor_used=job.executor_used,
        executor_label=EXECUTOR_LABELS.get(job.executor_used or "", None),
        outcome=job.outcome,
        root_alias=job.root_alias,
        workspace_branch=job.workspace_branch,
        workspace_snapshot_digest=job.workspace_snapshot_digest,
        failure_reason=job.failure_reason,
        cancel_requested=job.cancel_requested,
        attempt=job.attempt,
        steps=[
            CoworkJobStepRead(
                id=item.id,
                ordinal=item.ordinal,
                kind=item.kind,
                state=item.state,
                label=item.label,
                retryable=item.retryable,
                attempt=item.attempt,
                error_detail=item.error_detail,
                started_at=item.started_at,
                completed_at=item.completed_at,
            )
            for item in steps
        ],
        browser_task=await _browser_task_read(db, job),
        result=job_result(job),
        latest_sequence=int(latest.scalar_one_or_none() or 0),
        created_at=job.created_at,
        updated_at=job.updated_at,
        completed_at=job.completed_at,
    )


@router.post("/jobs", response_model=CoworkJobRead, summary="Create a durable Cowork job")
async def post_job(
    payload: CoworkJobCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    from app.core.marcellus.workspace import _get_conversation, _require_owner

    tenant_id = resolve_tenant(user, payload.tenant_id)
    enforce_ai_rate_limit(actor_id(user))
    conversation = await _get_conversation(db, tenant_id, payload.conversation_id)
    _require_owner(user, conversation.owner_id)

    # Bind the canonical workspace once, at creation. Re-resolving it later would
    # let a project switch retarget an in-flight job at the wrong folder.
    binding = get_binding(tenant_id, conversation.project_id) if conversation.project_id else None
    job = await jobs.create_job(
        db,
        tenant_id=tenant_id,
        owner_id=conversation.owner_id,
        conversation=conversation,
        request={
            "turn": payload.turn.model_dump(mode="json"),
            "inspect_workspace": payload.inspect_workspace,
            "user": {k: user.get(k) for k in ("sub", "id", "email", "role", "tenant_id", "tid")},
            "actor_id": actor_id(user),
            "source": payload.turn.source,
            "runtime_group": payload.turn.runtime_group,
        },
        root_token=(binding or {}).get("token"),
        root_alias=(binding or {}).get("path_alias") or (binding or {}).get("name"),
        idempotency_key=payload.idempotency_key,
        executor_preference=payload.executor,
    )
    await db.commit()
    if job.state == states.QUEUED:
        await jobs.spawn(job.id, tenant_id, run_job)
    await db.refresh(job)
    return await _job_read(db, job)


@router.get("/jobs", response_model=list[CoworkJobRead], summary="List Cowork jobs")
async def get_jobs(
    tenant_id: str = Query(default="global", max_length=128),
    conversation_id: uuid.UUID | None = Query(default=None),
    active_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, tenant_id)
    query = select(CoworkJob).where(CoworkJob.tenant_id == scoped)
    from app.core.marcellus.workspace import _can_read_all

    if not _can_read_all(user):
        query = query.where(CoworkJob.owner_id == actor_id(user))
    if conversation_id is not None:
        query = query.where(CoworkJob.conversation_id == conversation_id)
    if active_only:
        query = query.where(CoworkJob.state.notin_(tuple(states.TERMINAL_STATES)))
    result = await db.execute(query.order_by(CoworkJob.created_at.desc()).limit(limit))
    return [await _job_read(db, item) for item in result.scalars().all()]


@router.get("/jobs/{job_id}", response_model=CoworkJobRead, summary="Read one Cowork job")
async def get_job(
    job_id: uuid.UUID,
    tenant_id: str = Query(default="global", max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    return await _job_read(db, job)


@router.get(
    "/jobs/{job_id}/events",
    response_model=list[CoworkJobEventRead],
    summary="Poll the durable Cowork job timeline",
)
async def get_job_events(
    job_id: uuid.UUID,
    tenant_id: str = Query(default="global", max_length=128),
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    events = await jobs.list_events(db, job, after_sequence=after_sequence, limit=limit)
    return [
        CoworkJobEventRead(
            sequence=item.sequence,
            event_type=item.event_type,
            state=item.state,
            step_id=item.step_id,
            payload=jobs.event_payload(item),
            created_at=item.created_at,
        )
        for item in events
    ]


@router.get("/jobs/{job_id}/stream", summary="Stream the durable Cowork job timeline")
async def get_job_stream(
    job_id: uuid.UUID,
    request: Request,
    tenant_id: str = Query(default="global", max_length=128),
    after_sequence: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    job_uuid = job.id
    heartbeat = max(0.05, float(settings.WORKSPACE_STREAM_HEARTBEAT_SECONDS))

    async def events():
        cursor = after_sequence
        # Each poll uses a short-lived session of its own so a long stream never
        # pins the request's transaction open, and a client that vanishes takes
        # nothing down with it -- the job keeps running regardless.
        while True:
            if await request.is_disconnected():
                return
            async with jobs.session_factory() as session:
                current = await session.get(CoworkJob, job_uuid)
                if current is None:
                    return
                pending = await jobs.list_events(session, current, after_sequence=cursor)
                for item in pending:
                    cursor = item.sequence
                    yield _sse(
                        item.event_type,
                        {
                            "sequence": item.sequence,
                            "state": item.state,
                            "step_id": str(item.step_id) if item.step_id else None,
                            "payload": jobs.event_payload(item),
                        },
                    )
                terminal = states.is_terminal(current.state)
                suspended = current.state in states.SUSPENDED_STATES
            if terminal:
                yield _sse("job_finished", {"state": current.state, "sequence": cursor})
                return
            if suspended and not pending:
                # Waiting on a human: report it and let the client decide whether
                # to keep the stream open rather than burning a socket forever.
                yield _sse("job_suspended", {"state": current.state, "sequence": cursor})
            if not pending:
                yield _sse("heartbeat", {"sequence": cursor})
            await asyncio.sleep(heartbeat)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/jobs/{job_id}/result",
    response_model=CoworkJobResultRead,
    summary="Read the final Cowork job result",
)
async def get_job_result(
    job_id: uuid.UUID,
    tenant_id: str = Query(default="global", max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    return CoworkJobResultRead(
        job_id=job.id,
        state=job.state,
        outcome=job.outcome,
        result=job_result(job),
        failure_reason=job.failure_reason,
    )


@router.get(
    "/executors",
    response_model=CoworkExecutorStatusRead,
    summary="Report governed executor availability",
)
async def get_executors(
    tenant_id: str = Query(default="global", max_length=128),
    project_id: uuid.UUID | None = Query(default=None),
    preference: str = Query(default="auto", max_length=32),
    user: dict = Depends(get_current_user),
):
    """Tell the UI which executors are actually connected for this project.

    Lets the Cowork activity panel show a real Executor field rather than
    inferring one, and lets it distinguish "no executor" from "not run yet".
    """
    scoped = resolve_tenant(user, tenant_id)
    binding = get_binding(scoped, project_id) if project_id else None
    token = (binding or {}).get("token")
    report = await availability_report(token)
    executor, availability = await resolve_executor(preference, token=token)
    return CoworkExecutorStatusRead(
        executors=[CoworkExecutorRead(**item) for item in report],
        selected=availability.executor if executor is not None else "unavailable",
        selected_label=EXECUTOR_LABELS.get(
            availability.executor if executor is not None else "unavailable", "unavailable"
        ),
        any_available=any(item["available"] for item in report),
    )


@router.post("/jobs/{job_id}/cancel", response_model=CoworkJobRead, summary="Cancel a Cowork job")
async def post_job_cancel(
    job_id: uuid.UUID,
    payload: CoworkResumeRequest = Body(default_factory=CoworkResumeRequest),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, payload.tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    await jobs.request_cancel(db, job)
    await db.commit()
    await db.refresh(job)
    return await _job_read(db, job)


@router.post("/jobs/{job_id}/retry", response_model=CoworkJobRead, summary="Retry a failed Cowork step")
async def post_job_retry(
    job_id: uuid.UUID,
    payload: CoworkRetryRequest = Body(default_factory=CoworkRetryRequest),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, payload.tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    steps = await jobs.list_steps(db, job)
    target = None
    if payload.step_id is not None:
        target = next((item for item in steps if item.id == payload.step_id), None)
    else:
        target = next((item for item in reversed(steps) if item.state == "failed"), None)
    if target is None or not target.retryable:
        from fastapi import HTTPException, status as http_status

        raise HTTPException(
            status_code=http_status.HTTP_409_CONFLICT,
            detail="There is no retryable step for this job",
        )
    target.state = states.QUEUED
    target.error_detail = None
    job.cancel_requested = False
    job.failure_reason = None
    job.state = states.QUEUED
    job.completed_at = None
    job.lease_owner = None
    job.lease_expires_at = None
    await jobs.append_event(
        db, job, event_type="step_retry_requested", step_id=target.id, payload={"kind": target.kind}
    )
    await db.commit()
    await jobs.spawn(job.id, scoped, run_job)
    await db.refresh(job)
    return await _job_read(db, job)


@router.post("/jobs/{job_id}/resume", response_model=CoworkJobRead, summary="Resume an interrupted Cowork job")
async def post_job_resume(
    job_id: uuid.UUID,
    payload: CoworkResumeRequest = Body(default_factory=CoworkResumeRequest),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, payload.tenant_id)
    job = await jobs.get_job(db, scoped, job_id)
    jobs.require_owner(user, job)
    if states.is_terminal(job.state):
        return await _job_read(db, job)
    if not jobs.lease_is_stale(job):
        # Someone is genuinely still driving it; resuming would duplicate work.
        await jobs.append_event(db, job, event_type="resume_noop", payload={"reason": "lease_active"})
        await db.commit()
        return await _job_read(db, job)
    await jobs.append_event(db, job, event_type="resume_requested", payload={})
    await db.commit()
    await jobs.spawn(job.id, scoped, run_job)
    await db.refresh(job)
    return await _job_read(db, job)


@router.post(
    "/browser/ack",
    response_model=CoworkBrowserTaskRead,
    summary="Companion acknowledges a browser task",
)
async def post_browser_ack(
    payload: CoworkBrowserAck,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, payload.tenant_id)
    return await acknowledge_browser_task(db, scoped, payload, user=user)


@router.post(
    "/browser/progress",
    response_model=CoworkBrowserTaskRead,
    summary="Companion reports browser task progress",
)
async def post_browser_progress(
    payload: CoworkBrowserProgress,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, payload.tenant_id)
    return await record_browser_progress(db, scoped, payload, user=user)


@router.post(
    "/browser/complete",
    response_model=CoworkBrowserTaskRead,
    summary="Companion delivers the final browser response",
)
async def post_browser_complete(
    payload: CoworkBrowserComplete,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scoped = resolve_tenant(user, payload.tenant_id)
    return await complete_browser_task(db, scoped, payload, user=user)
