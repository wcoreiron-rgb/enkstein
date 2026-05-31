"""
RegentClaw — Schedule CRUD + Manual Trigger Routes (Async)
"""
import uuid
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, update

from app.core.database import get_db
from app.models.agent import Schedule, AgentRun, Agent, RunStatus, ScheduleFrequency
from app.schemas.agent import (
    ScheduleCreate, ScheduleUpdate, ScheduleRead,
    AgentRunRead, AgentTriggerResponse,
)
from app.core.swarm.schemas import SwarmJobCreate
from app.core.swarm.orchestrator import create_swarm_job, run_swarm_job_in_session

router = APIRouter(prefix="/schedules", tags=["Schedules"])


def _next_run_for(freq: ScheduleFrequency) -> Optional[datetime]:
    now = datetime.now(timezone.utc)
    delta_map = {
        ScheduleFrequency.MANUAL:        None,
        ScheduleFrequency.EVERY_15_MIN:  timedelta(minutes=15),
        ScheduleFrequency.HOURLY:        timedelta(hours=1),
        ScheduleFrequency.EVERY_6_HOURS: timedelta(hours=6),
        ScheduleFrequency.DAILY:         timedelta(days=1),
        ScheduleFrequency.WEEKLY:        timedelta(weeks=1),
        ScheduleFrequency.MONTHLY:       timedelta(days=30),
    }
    delta = delta_map.get(freq)
    return (now + delta) if delta else None


# ─── Schedule CRUD ────────────────────────────

@router.get("", response_model=List[ScheduleRead])
async def list_schedules(
    agent_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Schedule)
    if agent_id:
        q = q.where(Schedule.agent_id == agent_id)
    if status:
        q = q.where(Schedule.status == status)
    q = q.order_by(Schedule.next_run_at.asc().nullslast())
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=ScheduleRead, status_code=201)
async def create_schedule(body: ScheduleCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == body.agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    sched = Schedule(**body.model_dump())
    sched.next_run_at = _next_run_for(body.frequency)
    db.add(sched)
    await db.commit()
    await db.refresh(sched)
    return sched


@router.get("/{schedule_id}", response_model=ScheduleRead)
async def get_schedule(schedule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return sched


@router.patch("/{schedule_id}", response_model=ScheduleRead)
async def update_schedule(
    schedule_id: uuid.UUID,
    body: ScheduleUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    updates = body.model_dump(exclude_unset=True)
    for k, v in updates.items():
        setattr(sched, k, v)

    if "frequency" in updates:
        sched.next_run_at = _next_run_for(sched.frequency)

    await db.commit()
    await db.refresh(sched)
    return sched


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    # Preserve historical run records while allowing schedule deletion.
    await db.execute(
        update(AgentRun)
        .where(AgentRun.schedule_id == schedule_id)
        .values(schedule_id=None)
    )
    await db.delete(sched)
    await db.commit()


# ─── Manual Trigger ───────────────────────────

@router.post("/{schedule_id}/run", response_model=AgentTriggerResponse, status_code=202)
async def trigger_schedule(
    schedule_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if sched.status == "disabled":
        raise HTTPException(status_code=400, detail="Schedule is disabled")

    agent_result = await db.execute(select(Agent).where(Agent.id == sched.agent_id))
    agent = agent_result.scalar_one_or_none()
    if not agent or agent.status != "active":
        raise HTTPException(status_code=400, detail="Agent is not active")

    run = AgentRun(
        agent_id=sched.agent_id,
        schedule_id=schedule_id,
        status=RunStatus.PENDING,
        execution_mode=agent.execution_mode,
        triggered_by="manual_schedule",
    )
    db.add(run)

    sched.run_count += 1
    sched.last_run_at = datetime.now(timezone.utc)
    sched.next_run_at = _next_run_for(sched.frequency)

    await db.commit()
    await db.refresh(run)

    run_id = run.id
    background_tasks.add_task(_run_schedule, run_id)

    return AgentTriggerResponse(
        run_id=run_id,
        status=RunStatus.PENDING,
        message=f"Schedule run triggered for agent '{agent.name}' in {agent.execution_mode} mode",
    )


@router.post("/{schedule_id}/run-swarm", status_code=202)
async def trigger_schedule_swarm(
    schedule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Manual schedule trigger for SWARM_JOB actions.
    Reads swarm config from schedule.notes JSON.
    """
    result = await db.execute(select(Schedule).where(Schedule.id == schedule_id))
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if sched.status == "disabled":
        raise HTTPException(status_code=400, detail="Schedule is disabled")

    import json
    try:
        cfg = json.loads(sched.notes or "{}")
    except Exception:
        raise HTTPException(status_code=400, detail="Schedule notes must be valid JSON for swarm execution")

    action_type = str(cfg.get("type", "SWARM_JOB")).upper()
    if action_type != "SWARM_JOB":
        raise HTTPException(status_code=400, detail="Schedule notes type must be SWARM_JOB")

    action = cfg.get("action", cfg)
    payload = SwarmJobCreate(
        name=action.get("name") or f"Scheduled Swarm: {sched.name}",
        profile=action.get("profile", "DEEP_INVESTIGATION"),
        requested_by=sched.owner_id or "manual_schedule",
        trigger_type="schedule",
        classification=action.get("classification", "internal"),
        participants=action.get("participants", []),
        task_type=action.get("task_type", "analyze"),
        input=action.get("input", {}),
        parallelism=int(action.get("parallelism", 3)),
        model_profile=action.get("model_profile"),
    )
    job = await create_swarm_job(db, payload)
    await run_swarm_job_in_session(db, job.id)
    return {
        "job_id": str(job.id),
        "status": job.status.value,
        "message": f"Schedule '{sched.name}' triggered swarm job '{job.name}'",
    }


# ─── Schedule Run History ─────────────────────

@router.get("/{schedule_id}/runs", response_model=List[AgentRunRead])
async def schedule_runs(
    schedule_id: uuid.UUID,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(AgentRun)
        .where(AgentRun.schedule_id == schedule_id)
        .order_by(desc(AgentRun.created_at))
        .limit(limit)
    )
    result = await db.execute(q)
    return result.scalars().all()


# ─── Background task helper ───────────────────

async def _run_schedule(run_id: uuid.UUID):
    from app.core.database import AsyncSessionLocal
    from app.services.agent_runner import AgentRunner
    async with AsyncSessionLocal() as db:
        runner = AgentRunner(db)
        await runner.execute(run_id)
