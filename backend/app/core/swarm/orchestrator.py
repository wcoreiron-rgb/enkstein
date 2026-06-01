from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Awaitable, Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.swarm.aggregator import aggregate_task_outputs
from app.core.swarm.dispatcher import execute_task, execute_task_by_id
from app.core.swarm.judge import judge_swarm_result_with_modelclaw
from app.core.swarm.planner import select_participants
from app.core.swarm.schemas import SwarmJobCreate
from app.models.swarm import SwarmJob, SwarmJobStatus, SwarmTask, SwarmTaskStatus
from app.services.memory_runtime import propose_swarm_memory_update


async def create_swarm_job(db: AsyncSession, payload: SwarmJobCreate) -> SwarmJob:
    participants = select_participants(payload)
    job = SwarmJob(
        name=payload.name,
        profile=payload.profile,
        status=SwarmJobStatus.PENDING,
        requested_by=payload.requested_by,
        trigger_type=payload.trigger_type,
        input_json=json.dumps(payload.input),
        classification=payload.classification,
        participants_json=json.dumps(participants),
        parallelism=payload.parallelism,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    for claw in participants:
        task = SwarmTask(
            swarm_job_id=job.id,
            claw=claw,
            task_type=payload.task_type,
            status=SwarmTaskStatus.PENDING,
            model_profile=payload.model_profile,
            input_json=json.dumps(payload.input),
        )
        db.add(task)
    await db.commit()
    return job


async def run_swarm_job_in_session(db: AsyncSession, job_id: UUID) -> None:
    """Execute a swarm job using the provided DB session."""
    result = await db.execute(select(SwarmJob).where(SwarmJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        return
    if job.status in {SwarmJobStatus.CANCELLED, SwarmJobStatus.COMPLETED}:
        return

    job.status = SwarmJobStatus.RUNNING
    job.started_at = datetime.utcnow()
    await db.commit()

    task_result = await db.execute(select(SwarmTask).where(SwarmTask.swarm_job_id == job.id))
    tasks = task_result.scalars().all()
    try:
        normalized_outputs: list[dict] = []
        failures: list[Exception] = []
        for task in tasks:
            if job.status == SwarmJobStatus.CANCELLED:
                task.status = SwarmTaskStatus.CANCELLED
                await db.commit()
                continue
            try:
                out = await execute_task(db, task)
                normalized_outputs.append(out)
            except Exception as exc:  # pragma: no cover - defensive failure capture
                failures.append(exc)

        if job.status == SwarmJobStatus.CANCELLED:
            return

        if failures and not normalized_outputs:
            job.status = SwarmJobStatus.FAILED
            job.error_message = "; ".join(str(e) for e in failures[:3])
            job.completed_at = datetime.utcnow()
            await db.commit()
            return

        aggregate = aggregate_task_outputs(normalized_outputs)
        judged = await judge_swarm_result_with_modelclaw(
            db,
            job.name,
            aggregate,
            len(tasks),
            classification=job.classification,
            swarm_job_id=str(job.id),
        )
        judged["memory_update"] = await propose_swarm_memory_update(db, job, judged, aggregate)
        job.confidence = judged["confidence"]
        job.overall_severity = judged["overall_severity"]
        job.final_summary = judged["executive_summary"]
        job.result_json = json.dumps(judged)
        job.status = SwarmJobStatus.REQUIRES_APPROVAL if judged["requires_human_approval"] else SwarmJobStatus.COMPLETED
        job.completed_at = datetime.utcnow()
        await db.commit()
    except Exception as exc:
        job.status = SwarmJobStatus.FAILED
        job.error_message = str(exc)
        job.completed_at = datetime.utcnow()
        await db.commit()


async def _run_bounded_parallel_tasks(
    task_ids: list[UUID],
    parallelism: int,
    runner: Callable[[UUID], Awaitable[dict | None]],
) -> tuple[list[dict], list[Exception]]:
    semaphore = asyncio.Semaphore(max(1, parallelism))
    outputs: list[dict] = []
    failures: list[Exception] = []

    async def _run(task_id: UUID) -> None:
        async with semaphore:
            try:
                out = await runner(task_id)
                if out:
                    outputs.append(out)
            except Exception as exc:  # pragma: no cover - defensive failure capture
                failures.append(exc)

    await asyncio.gather(*(_run(task_id) for task_id in task_ids))
    return outputs, failures


async def run_swarm_job(job_id: UUID) -> None:
    """
    Executes a swarm job with bounded parallelism for production/background runs.
    Uses a fresh DB session because this is called from background tasks.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(SwarmJob).where(SwarmJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            return
        if job.status in {SwarmJobStatus.CANCELLED, SwarmJobStatus.COMPLETED}:
            return

        job.status = SwarmJobStatus.RUNNING
        job.started_at = datetime.utcnow()
        await db.commit()

        task_result = await db.execute(select(SwarmTask).where(SwarmTask.swarm_job_id == job.id))
        tasks = task_result.scalars().all()
        task_ids = [task.id for task in tasks if task.status != SwarmTaskStatus.CANCELLED]

        try:
            normalized_outputs, failures = await _run_bounded_parallel_tasks(
                task_ids=task_ids,
                parallelism=job.parallelism or 1,
                runner=execute_task_by_id,
            )

            await db.refresh(job)
            if job.status == SwarmJobStatus.CANCELLED:
                return

            if failures and not normalized_outputs:
                job.status = SwarmJobStatus.FAILED
                job.error_message = "; ".join(str(e) for e in failures[:3])
                job.completed_at = datetime.utcnow()
                await db.commit()
                return

            aggregate = aggregate_task_outputs(normalized_outputs)
            judged = await judge_swarm_result_with_modelclaw(
                db,
                job.name,
                aggregate,
                len(tasks),
                classification=job.classification,
                swarm_job_id=str(job.id),
            )
            judged["memory_update"] = await propose_swarm_memory_update(db, job, judged, aggregate)
            job.confidence = judged["confidence"]
            job.overall_severity = judged["overall_severity"]
            job.final_summary = judged["executive_summary"]
            job.result_json = json.dumps(judged)
            job.status = SwarmJobStatus.REQUIRES_APPROVAL if judged["requires_human_approval"] else SwarmJobStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            await db.commit()
        except Exception as exc:
            job.status = SwarmJobStatus.FAILED
            job.error_message = str(exc)
            job.completed_at = datetime.utcnow()
            await db.commit()
