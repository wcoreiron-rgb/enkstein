"""
Enkstein — Agent CRUD + Run Trigger Routes (Async)
"""
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.agent import Agent, AgentRun, RunStatus, ExecutionMode
from app.schemas.agent import (
    AgentCreate, AgentUpdate, AgentRead,
    AgentRunRead, AgentTriggerRequest, AgentTriggerResponse,
    ApprovalAction,
)
from app.services.agent_runner import AgentRunner

router = APIRouter(prefix="/agents", tags=["Agents"])


# ─── Agent CRUD ───────────────────────────────

@router.get("", response_model=List[AgentRead])
async def list_agents(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    claw: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Agent)
    if status:
        q = q.where(Agent.status == status)
    if category:
        q = q.where(Agent.category == category)
    if claw:
        q = q.where(Agent.claw == claw)
    q = q.order_by(Agent.name)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=AgentRead, status_code=201)
async def create_agent(body: AgentCreate, db: AsyncSession = Depends(get_db)):
    agent = Agent(**body.model_dump())
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.get("/{agent_id}", response_model=AgentRead)
async def get_agent(agent_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.patch("/{agent_id}", response_model=AgentRead)
async def update_agent(agent_id: uuid.UUID, body: AgentUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(agent, k, v)
    await db.commit()
    await db.refresh(agent)
    return agent


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(agent_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.is_builtin:
        raise HTTPException(status_code=400, detail="Cannot delete a built-in agent")
    await db.delete(agent)
    await db.commit()


# ─── Manual Run Trigger ───────────────────────

@router.post("/{agent_id}/run", response_model=AgentTriggerResponse, status_code=202)
async def trigger_agent(
    agent_id: uuid.UUID,
    body: AgentTriggerRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status != "active":
        raise HTTPException(status_code=400, detail=f"Agent is {agent.status}, not active")

    effective_mode = body.execution_mode or agent.execution_mode

    run = AgentRun(
        agent_id=agent_id,
        schedule_id=None,
        status=RunStatus.PENDING,
        execution_mode=effective_mode,
        triggered_by=body.triggered_by,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    run_id = run.id
    background_tasks.add_task(_run_agent, run_id)

    return AgentTriggerResponse(
        run_id=run_id,
        status=RunStatus.PENDING,
        message=f"Agent run queued in {effective_mode} mode",
    )


# ─── Run History ──────────────────────────────

@router.get("/{agent_id}/runs", response_model=List[AgentRunRead])
async def get_agent_runs(
    agent_id: uuid.UUID,
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(AgentRun)
        .where(AgentRun.agent_id == agent_id)
        .order_by(desc(AgentRun.created_at))
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{agent_id}/runs/{run_id}", response_model=AgentRunRead)
async def get_run(agent_id: uuid.UUID, run_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AgentRun).where(AgentRun.id == run_id, AgentRun.agent_id == agent_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


# ─── Approval (Assist mode) ───────────────────

@router.post("/{agent_id}/runs/{run_id}/approve", response_model=AgentRunRead)
async def approve_action(
    agent_id: uuid.UUID,
    run_id: uuid.UUID,
    body: ApprovalAction,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AgentRun).where(AgentRun.id == run_id, AgentRun.agent_id == agent_id)
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != RunStatus.AWAITING:
        raise HTTPException(status_code=400, detail="Run is not awaiting approval")

    background_tasks.add_task(_process_approval, run_id, body)
    await db.refresh(run)
    return run


# ─── Background task helpers (open their own DB session) ─────────────────────

async def _run_agent(run_id: uuid.UUID):
    from app.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        runner = AgentRunner(db)
        await runner.execute(run_id)


async def _process_approval(run_id: uuid.UUID, approval: ApprovalAction):
    from app.core.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        runner = AgentRunner(db)
        await runner.process_approval(run_id, approval)
