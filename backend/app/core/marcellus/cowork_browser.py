"""Durable Browser Companion task protocol.

The Companion relays a visible, already-signed-in provider page. It is an
advisor and research engine only: nothing in this module can write to the
filesystem, and a Companion response reaches disk solely by being handed to the
deterministic governed writer like any other Brain answer.

Two properties matter most here:

* **No duplicate prompts.** A task is keyed by ``submission_key``. A reconnect,
  a retried POST, or a resumed job finds the existing row and continues waiting
  on the provider conversation already in flight.
* **No false timeouts.** A legitimately slow page can take minutes. Liveness is
  judged by the Companion's heartbeat, not by how long the HTTP client stayed
  attached.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus import cowork_jobs as jobs
from app.core.marcellus.cowork_schemas import (
    CoworkBrowserAck,
    CoworkBrowserComplete,
    CoworkBrowserProgress,
    CoworkBrowserTaskRead,
)
from app.core.marcellus.crypto import encrypt_json
from app.models.marcellus import CoworkBrowserTask, CoworkJob


#: How long a Companion may go silent before the task is considered
#: disconnected. Deliberately generous: a browser tab generating a long answer
#: is normal, and killing it early is the failure mode this replaces.
HEARTBEAT_GRACE_SECONDS = 180

#: Operator-facing states, mapped one-to-one to the required vocabulary.
DISPLAY_STATES = {
    "submitted": "Waiting for {provider}",
    "acknowledged": "Waiting for {provider}",
    "composing": "{provider} is composing",
    "streaming": "{provider} is streaming",
    "received": "Response received",
    "download_detected": "Download detected",
    "preparing_files": "Preparing files locally",
    "incomplete": "Browser response incomplete",
    "disconnected": "Browser session disconnected",
}

_PROVIDER_LABELS = {
    "chatgpt_browser": "ChatGPT",
    "claude_browser": "Claude",
    "gemini_browser": "Gemini",
}


def display_state(task: CoworkBrowserTask) -> str:
    template = DISPLAY_STATES.get(task.state, "Waiting for {provider}")
    return template.format(provider=_PROVIDER_LABELS.get(task.provider, "the browser Brain"))


def is_stale(task: CoworkBrowserTask, *, now: datetime | None = None) -> bool:
    """True when the Companion has stopped reporting for longer than the grace."""
    reference = task.heartbeat_at or task.acknowledged_at or task.created_at
    if reference is None:
        return False
    return (now or datetime.utcnow()) - reference > timedelta(seconds=HEARTBEAT_GRACE_SECONDS)


def _read(task: CoworkBrowserTask) -> CoworkBrowserTaskRead:
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


async def _resolve(
    db: AsyncSession, tenant_id: str, submission_key: str, *, user: dict
) -> tuple[CoworkBrowserTask, CoworkJob]:
    result = await db.execute(
        select(CoworkBrowserTask).where(
            CoworkBrowserTask.tenant_id == tenant_id,
            CoworkBrowserTask.submission_key == submission_key,
        )
    )
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Browser task not found")
    job = await jobs.get_job(db, tenant_id, task.job_id)
    jobs.require_owner(user, job)
    return task, job


async def acknowledge_browser_task(
    db: AsyncSession, tenant_id: str, payload: CoworkBrowserAck, *, user: dict
) -> CoworkBrowserTaskRead:
    task, job = await _resolve(db, tenant_id, payload.submission_key, user=user)
    if task.state in {"received", "incomplete"}:
        # Already delivered; acknowledging again must not reopen or re-prompt it.
        return _read(task)
    task.state = "acknowledged"
    task.acknowledged_at = datetime.utcnow()
    task.heartbeat_at = datetime.utcnow()
    if payload.provider_tab_id:
        task.provider_tab_id = payload.provider_tab_id[:128]
    if payload.provider_conversation_id:
        task.provider_conversation_id = payload.provider_conversation_id[:255]
    await jobs.append_event(
        db,
        job,
        event_type="browser_state",
        payload={"provider": task.provider, "state": task.state, "label": display_state(task)},
    )
    await db.commit()
    return _read(task)


async def record_browser_progress(
    db: AsyncSession, tenant_id: str, payload: CoworkBrowserProgress, *, user: dict
) -> CoworkBrowserTaskRead:
    task, job = await _resolve(db, tenant_id, payload.submission_key, user=user)
    if task.completed_at is not None:
        return _read(task)
    task.state = payload.state if payload.state != "waiting" else "acknowledged"
    task.heartbeat_at = datetime.utcnow()
    if payload.chunk:
        task.chunk_count += 1
    await jobs.append_event(
        db,
        job,
        event_type="browser_state",
        payload={
            "provider": task.provider,
            "state": task.state,
            "label": display_state(task),
            "chunk_count": task.chunk_count,
        },
    )
    await db.commit()
    return _read(task)


async def complete_browser_task(
    db: AsyncSession, tenant_id: str, payload: CoworkBrowserComplete, *, user: dict
) -> CoworkBrowserTaskRead:
    task, job = await _resolve(db, tenant_id, payload.submission_key, user=user)
    if task.completed_at is not None:
        # A late duplicate delivery: keep the first authoritative response.
        return _read(task)
    ciphertext, digest = encrypt_json({"response": payload.response})
    task.response_ciphertext = ciphertext
    task.response_digest = digest
    task.attachments_json = json.dumps(payload.attachments[:20], separators=(",", ":"))
    task.truncated = bool(payload.truncated)
    task.heartbeat_at = datetime.utcnow()
    task.completed_at = datetime.utcnow()
    if payload.failure_reason:
        task.state = "disconnected"
        task.failure_reason = payload.failure_reason[:500]
    elif payload.truncated:
        task.state = "incomplete"
    elif payload.attachments:
        task.state = "download_detected"
    else:
        task.state = "received"
    await jobs.append_event(
        db,
        job,
        event_type="browser_state",
        payload={
            "provider": task.provider,
            "state": task.state,
            "label": display_state(task),
            "attachments": len(payload.attachments),
            "truncated": task.truncated,
        },
    )
    await db.commit()
    return _read(task)
