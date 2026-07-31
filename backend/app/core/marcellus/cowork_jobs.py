"""Durable Cowork job store and out-of-band coordinator.

The authoritative state of a Cowork request lives in the database, never in the
HTTP request or the browser. The practical consequences:

* the runner owns its **own** session, so finishing work is not tied to the
  lifetime of the request that created the job (a client disconnect rolls back
  only the request's session, never the job's);
* every observable transition is appended to ``CoworkJobEvent``, so a client
  that reconnects replays exactly what it missed instead of losing the run;
* a job is claimed under a lease, so a process that dies mid-run leaves a stale
  lease that ``resume`` can safely take over rather than an orphan that appears
  to be running forever.

The Brain remains an advisor here. This module never writes to the filesystem
directly: file effects go through the existing deterministic governed writer in
``workspace.py`` (``_auto_apply_changes`` / ``_persist_change_proposals``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.marcellus import cowork_states as states
from app.core.marcellus.crypto import decrypt_json, encrypt_json
from app.models.marcellus import (
    CortexConversation,
    CoworkBrowserTask,
    CoworkJob,
    CoworkJobEvent,
    CoworkJobStep,
)

logger = logging.getLogger("marcellus.cowork.jobs")

# How long a runner may hold a job before another process may take it over.
# Comfortably longer than the browser Brain budget so a legitimately slow
# provider response is never mistaken for a dead runner.
LEASE_SECONDS = 1_200

#: Identifies the process holding a lease. Stable for the life of the worker.
_RUNNER_ID = f"{os.getpid()}:{uuid.uuid4().hex[:8]}"

#: Live in-process tasks, so cancel can interrupt promptly rather than waiting
#: for the next durable checkpoint. Losing this map (restart) costs nothing:
#: the durable lease and event log remain the source of truth.
_RUNNING: dict[uuid.UUID, asyncio.Task] = {}

#: Session factory the out-of-band runner uses. Indirected so a test harness can
#: point runners at its own engine; production always uses the app factory.
_SESSION_FACTORY = AsyncSessionLocal
#: When true, ``spawn`` awaits the runner instead of backgrounding it. Only a
#: test harness sets this, so assertions observe a settled job.
_INLINE = False


def configure_runner(session_factory=None, *, inline: bool | None = None) -> None:
    """Point the out-of-band runner at a different session factory (tests)."""
    global _SESSION_FACTORY, _INLINE
    if session_factory is not None:
        _SESSION_FACTORY = session_factory
    if inline is not None:
        _INLINE = inline


def reset_runner() -> None:
    global _SESSION_FACTORY, _INLINE
    _SESSION_FACTORY = AsyncSessionLocal
    _INLINE = False


def session_factory():
    """Session factory for durable reads outside a request's transaction."""
    return _SESSION_FACTORY()


def _now() -> datetime:
    return datetime.utcnow()


def digest_token(token: str) -> str:
    """Domain-separated digest of an opaque root binding token.

    Lets a job prove it is still bound to the same approved root without ever
    persisting the token (or the absolute host path) alongside job state.
    """
    material = "\x00".join(["marcellus.cowork.root.v1", token])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


async def _next_sequence(db: AsyncSession, job_id: uuid.UUID) -> int:
    result = await db.execute(
        select(func.max(CoworkJobEvent.sequence)).where(CoworkJobEvent.job_id == job_id)
    )
    return int(result.scalar_one_or_none() or 0) + 1


async def append_event(
    db: AsyncSession,
    job: CoworkJob,
    *,
    event_type: str,
    payload: dict[str, Any] | None = None,
    state: str | None = None,
    step_id: uuid.UUID | None = None,
) -> CoworkJobEvent:
    """Append one timeline entry. Retries once on a concurrent sequence clash."""
    body = payload or {}
    ciphertext, digest = encrypt_json(body)
    for _ in range(2):
        event = CoworkJobEvent(
            tenant_id=job.tenant_id,
            job_id=job.id,
            step_id=step_id,
            sequence=await _next_sequence(db, job.id),
            event_type=event_type[:64],
            state=state,
            payload_ciphertext=ciphertext,
            payload_digest=digest,
        )
        db.add(event)
        try:
            await db.flush()
            return event
        except IntegrityError:
            await db.rollback()
    raise RuntimeError("Cowork job event sequence could not be allocated")


def event_payload(event: CoworkJobEvent) -> dict[str, Any]:
    try:
        value = decrypt_json(event.payload_ciphertext, event.payload_digest)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


async def transition(
    db: AsyncSession,
    job: CoworkJob,
    target: str,
    *,
    detail: str | None = None,
    step_id: uuid.UUID | None = None,
) -> None:
    """Move a job to ``target``, recording the change on the durable timeline.

    An illegal transition is a programming error and is refused outright rather
    than silently coerced, so a job can never appear to have skipped a stage.
    """
    if job.state == target:
        return
    if not states.can_transition(job.state, target):
        raise RuntimeError(f"Illegal Cowork job transition {job.state} -> {target}")
    job.state = target
    job.updated_at = _now()
    if states.is_terminal(target):
        job.completed_at = _now()
        job.lease_owner = None
        job.lease_expires_at = None
        if target != states.COMPLETED and detail:
            job.failure_reason = detail[:2000]
    await append_event(
        db,
        job,
        event_type="state_changed",
        state=target,
        step_id=step_id,
        payload={"state": target, "detail": detail} if detail else {"state": target},
    )


async def get_job(db: AsyncSession, tenant_id: str, job_id: uuid.UUID) -> CoworkJob:
    result = await db.execute(
        select(CoworkJob).where(CoworkJob.tenant_id == tenant_id, CoworkJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    if job is None:
        # 404 rather than 403 so a job id cannot be probed across tenants.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Cowork job not found")
    return job


def require_owner(user: dict[str, Any], job: CoworkJob) -> None:
    from app.core.marcellus.workspace import _require_owner

    _require_owner(user, job.owner_id)


async def find_by_idempotency_key(
    db: AsyncSession, tenant_id: str, key: str | None
) -> CoworkJob | None:
    if not key:
        return None
    result = await db.execute(
        select(CoworkJob).where(
            CoworkJob.tenant_id == tenant_id, CoworkJob.idempotency_key == key
        )
    )
    return result.scalar_one_or_none()


async def create_job(
    db: AsyncSession,
    *,
    tenant_id: str,
    owner_id: str,
    conversation: CortexConversation,
    request: dict[str, Any],
    root_token: str | None,
    root_alias: str | None,
    idempotency_key: str | None = None,
    executor_preference: str = "auto",
) -> CoworkJob:
    """Create a durable job bound to exactly one project and one approved root."""
    existing = await find_by_idempotency_key(db, tenant_id, idempotency_key)
    if existing is not None:
        return existing
    ciphertext, digest = encrypt_json(request)
    job = CoworkJob(
        tenant_id=tenant_id,
        owner_id=owner_id,
        project_id=conversation.project_id,
        conversation_id=conversation.id,
        idempotency_key=idempotency_key,
        state=states.QUEUED,
        mode=conversation.mode,
        source=str(request.get("source") or conversation.selected_source)[:128],
        runtime_group=str(request.get("runtime_group") or "hybrid")[:32],
        classification=conversation.classification,
        root_token_digest=digest_token(root_token) if root_token else None,
        root_alias=(root_alias or None),
        executor_preference=(executor_preference or "auto")[:32],
        request_ciphertext=ciphertext,
        request_digest=digest,
    )
    db.add(job)
    try:
        await db.flush()
    except IntegrityError:
        # Two concurrent creates raced on the same idempotency key; the winner's
        # job is the one that matters, so return it instead of failing the call.
        await db.rollback()
        duplicate = await find_by_idempotency_key(db, tenant_id, idempotency_key)
        if duplicate is None:
            raise
        return duplicate
    await append_event(
        db,
        job,
        event_type="job_created",
        state=states.QUEUED,
        payload={
            "project_id": str(conversation.project_id) if conversation.project_id else None,
            "conversation_id": str(conversation.id),
            "root_alias": job.root_alias,
        },
    )
    return job


async def add_step(
    db: AsyncSession,
    job: CoworkJob,
    *,
    kind: str,
    label: str = "",
    retryable: bool = True,
) -> CoworkJobStep:
    result = await db.execute(
        select(func.max(CoworkJobStep.ordinal)).where(CoworkJobStep.job_id == job.id)
    )
    step = CoworkJobStep(
        tenant_id=job.tenant_id,
        job_id=job.id,
        ordinal=int(result.scalar_one_or_none() or 0) + 1,
        kind=kind[:64],
        label=label[:255],
        retryable=retryable,
        state=states.QUEUED,
    )
    db.add(step)
    await db.flush()
    return step


async def start_step(db: AsyncSession, job: CoworkJob, step: CoworkJobStep, state: str) -> None:
    step.state = state
    step.attempt += 1
    step.started_at = _now()
    await transition(db, job, state, step_id=step.id)
    await append_event(
        db,
        job,
        event_type="step_started",
        state=state,
        step_id=step.id,
        payload={"kind": step.kind, "label": step.label, "attempt": step.attempt},
    )


async def finish_step(
    db: AsyncSession,
    job: CoworkJob,
    step: CoworkJobStep,
    *,
    ok: bool,
    detail: str | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    step.state = "completed" if ok else "failed"
    step.completed_at = _now()
    if not ok:
        step.error_detail = (detail or "")[:2000] or None
    await append_event(
        db,
        job,
        event_type="step_completed" if ok else "step_failed",
        step_id=step.id,
        payload={"kind": step.kind, "detail": detail, **(payload or {})},
    )


async def list_events(
    db: AsyncSession, job: CoworkJob, *, after_sequence: int = 0, limit: int = 500
) -> list[CoworkJobEvent]:
    result = await db.execute(
        select(CoworkJobEvent)
        .where(CoworkJobEvent.job_id == job.id, CoworkJobEvent.sequence > after_sequence)
        .order_by(CoworkJobEvent.sequence)
        .limit(limit)
    )
    return list(result.scalars().all())


async def list_steps(db: AsyncSession, job: CoworkJob) -> list[CoworkJobStep]:
    result = await db.execute(
        select(CoworkJobStep)
        .where(CoworkJobStep.job_id == job.id)
        .order_by(CoworkJobStep.ordinal)
    )
    return list(result.scalars().all())


async def request_cancel(db: AsyncSession, job: CoworkJob) -> CoworkJob:
    """Ask a job to stop. Terminal jobs are left exactly as they are."""
    if states.is_terminal(job.state):
        return job
    job.cancel_requested = True
    await append_event(db, job, event_type="cancel_requested", payload={})
    # Kill any command this job still has running, including its child tree.
    # Done by durable execution id, so it works even when the request that
    # started the command belonged to a different process.
    await cancel_live_executions(db, job)
    task = _RUNNING.get(job.id)
    if task is not None and not task.done():
        task.cancel()
    await transition(db, job, states.CANCELLED, detail="Cancelled by the operator.")
    return job


async def cancel_live_executions(db: AsyncSession, job: CoworkJob) -> int:
    """Terminate every still-running command owned by this job."""
    from app.core.marcellus.cowork_executors import get_executor
    from app.models.marcellus import CoworkExecution

    result = await db.execute(
        select(CoworkExecution).where(
            CoworkExecution.tenant_id == job.tenant_id,
            CoworkExecution.job_id == job.id,
            CoworkExecution.status == "running",
        )
    )
    cancelled = 0
    for record in result.scalars().all():
        executor = get_executor(record.executor)
        if executor is None:
            continue
        try:
            stopped = await executor.cancel(execution_id=record.execution_id)
        except Exception:
            logger.warning("Execution cancellation failed for job %s", job.id)
            stopped = False
        record.cancelled = True
        record.status = "cancelled"
        record.completed_at = _now()
        if stopped:
            cancelled += 1
    if cancelled:
        await db.flush()
    return cancelled


def lease_is_stale(job: CoworkJob) -> bool:
    if job.lease_expires_at is None:
        return True
    return job.lease_expires_at <= _now()


async def claim(db: AsyncSession, job: CoworkJob) -> bool:
    """Take the lease if nobody live holds it. Returns False if already claimed.

    The conditional UPDATE is what makes this safe under concurrency: two
    processes resuming the same job cannot both win, so a job is never run twice.
    """
    if job.id in _RUNNING and not _RUNNING[job.id].done():
        return False
    deadline = _now() + timedelta(seconds=LEASE_SECONDS)
    result = await db.execute(
        update(CoworkJob)
        .where(
            CoworkJob.id == job.id,
            CoworkJob.tenant_id == job.tenant_id,
            (CoworkJob.lease_expires_at.is_(None)) | (CoworkJob.lease_expires_at <= _now()),
        )
        .values(lease_owner=_RUNNER_ID, lease_expires_at=deadline, attempt=CoworkJob.attempt + 1)
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        return False
    await db.refresh(job)
    return True


async def heartbeat(db: AsyncSession, job: CoworkJob) -> None:
    job.lease_expires_at = _now() + timedelta(seconds=LEASE_SECONDS)
    await db.flush()


async def browser_task_for(
    db: AsyncSession, job: CoworkJob, *, provider: str, submission_key: str
) -> tuple[CoworkBrowserTask, bool]:
    """Return the durable browser task for this submission key.

    The second element is True when the task already existed, which is the
    signal that the Companion must be *resumed* rather than re-prompted: a
    reconnect must never cause a second prompt to be typed into the provider.
    """
    result = await db.execute(
        select(CoworkBrowserTask).where(
            CoworkBrowserTask.tenant_id == job.tenant_id,
            CoworkBrowserTask.submission_key == submission_key,
        )
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        return existing, True
    task = CoworkBrowserTask(
        tenant_id=job.tenant_id,
        job_id=job.id,
        provider=provider[:64],
        submission_key=submission_key[:128],
        retry_token=uuid.uuid4().hex,
        state="submitted",
    )
    db.add(task)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        retry = await db.execute(
            select(CoworkBrowserTask).where(
                CoworkBrowserTask.tenant_id == job.tenant_id,
                CoworkBrowserTask.submission_key == submission_key,
            )
        )
        duplicate = retry.scalar_one_or_none()
        if duplicate is None:
            raise
        return duplicate, True
    return task, False


async def spawn(job_id: uuid.UUID, tenant_id: str, runner) -> None:
    """Run ``runner`` out-of-band on a session the request does not own.

    This is the mechanism that makes a job survive a disconnect: the request's
    session may be rolled back and closed the moment the client goes away, but
    the job keeps advancing on the session opened here.
    """
    if job_id in _RUNNING and not _RUNNING[job_id].done():
        return

    async def _run() -> None:
        try:
            async with _SESSION_FACTORY() as session:
                job = await session.get(CoworkJob, job_id)
                if job is None or job.tenant_id != tenant_id:
                    return
                if not await claim(session, job):
                    await session.commit()
                    return
                await session.commit()
                try:
                    await runner(session, job)
                    await session.commit()
                except asyncio.CancelledError:
                    await session.rollback()
                    fresh = await session.get(CoworkJob, job_id)
                    if fresh is not None and not states.is_terminal(fresh.state):
                        await transition(
                            session, fresh, states.CANCELLED, detail="The job was cancelled."
                        )
                        await session.commit()
                    raise
                except Exception:
                    # Never leak provider text, prompts, or paths into the
                    # durable record; the operator gets a safe reason and the
                    # exception type is preserved for the server log only.
                    logger.exception("Cowork job %s failed", job_id)
                    await session.rollback()
                    fresh = await session.get(CoworkJob, job_id)
                    if fresh is not None and not states.is_terminal(fresh.state):
                        await transition(
                            session,
                            fresh,
                            states.FAILED,
                            detail="The job could not be completed.",
                        )
                        await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Cowork job runner %s crashed", job_id)
        finally:
            _RUNNING.pop(job_id, None)

    if _INLINE:
        await _run()
        return
    _RUNNING[job_id] = asyncio.ensure_future(_run())


async def shutdown() -> None:
    """Cancel in-process runners; durable state stays recoverable via resume."""
    tasks = [task for task in _RUNNING.values() if not task.done()]
    for task in tasks:
        task.cancel()
    for task in tasks:
        with contextlib.suppress(BaseException):
            await task
    _RUNNING.clear()


async def recover_orphaned_jobs(session_factory=None) -> int:
    """Re-adopt jobs whose runner died (desktop restart, crash, redeploy).

    This is what makes durability real rather than nominal: an in-process task
    dies with the process, but the row does not. On startup every non-terminal
    job whose lease has expired is re-queued and spawned again, so a job that
    was mid-flight when the app quit continues instead of hanging forever.
    """
    from app.core.marcellus.cowork_runner import run_job

    factory = session_factory or _SESSION_FACTORY
    recovered = 0
    async with factory() as session:
        result = await session.execute(
            select(CoworkJob).where(
                CoworkJob.state.notin_(tuple(states.TERMINAL_STATES)),
                CoworkJob.state.notin_(tuple(states.SUSPENDED_STATES)),
                (CoworkJob.lease_expires_at.is_(None)) | (CoworkJob.lease_expires_at <= _now()),
            )
        )
        orphans = list(result.scalars().all())
        for job in orphans:
            await append_event(
                session,
                job,
                event_type="job_recovered",
                payload={"previous_state": job.state, "attempt": job.attempt},
            )
        if orphans:
            await session.commit()
    for job in orphans:
        await spawn(job.id, job.tenant_id, run_job)
        recovered += 1
    if recovered:
        logger.info("Recovered %s orphaned Cowork job(s) after restart", recovered)
    return recovered
