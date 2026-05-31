"""CoreOS — Orchestration (Workflow) routes."""
import json
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from uuid import UUID
from typing import Optional

from app.core.database import get_db
from app.models.workflow import Workflow, WorkflowRun
from app.schemas.workflow import (
    WorkflowCreate, WorkflowUpdate, WorkflowRead,
    WorkflowRunRead, WorkflowTriggerResponse,
)
from app.services.workflow_runner import execute_workflow

router = APIRouter(prefix="/orchestrations", tags=["Orchestrations"])


# ─── Workflow CRUD ──────────────────────────────────────────────────────────

@router.get("", response_model=list[WorkflowRead])
async def list_workflows(
    category: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Workflow).order_by(Workflow.name)
    if category:
        q = q.where(Workflow.category == category)
    if is_active is not None:
        q = q.where(Workflow.is_active == is_active)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=WorkflowRead, status_code=201)
async def create_workflow(payload: WorkflowCreate, db: AsyncSession = Depends(get_db)):
    data = payload.model_dump()
    # Auto-count steps
    try:
        steps = json.loads(data.get("steps_json", "[]"))
        data["step_count"] = len(steps)
    except Exception:
        data["step_count"] = 0
    workflow = Workflow(**data)
    db.add(workflow)
    await db.commit()
    await db.refresh(workflow)
    return workflow


@router.get("/{workflow_id}", response_model=WorkflowRead)
async def get_workflow(workflow_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workflow).where(Workflow.id == UUID(workflow_id)))
    wf = result.scalar_one_or_none()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return wf


@router.patch("/{workflow_id}", response_model=WorkflowRead)
async def update_workflow(workflow_id: str, payload: WorkflowUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workflow).where(Workflow.id == UUID(workflow_id)))
    wf = result.scalar_one_or_none()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    data = payload.model_dump(exclude_none=True)
    # Auto-count steps if steps_json changed
    if "steps_json" in data:
        try:
            data["step_count"] = len(json.loads(data["steps_json"]))
        except Exception:
            pass
    for field, value in data.items():
        setattr(wf, field, value)
    await db.commit()
    await db.refresh(wf)
    return wf


@router.delete("/{workflow_id}", status_code=204)
async def delete_workflow(workflow_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Workflow).where(Workflow.id == UUID(workflow_id)))
    wf = result.scalar_one_or_none()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    await db.delete(wf)
    await db.commit()


# ─── Workflow execution ──────────────────────────────────────────────────────

@router.post("/{workflow_id}/run", response_model=WorkflowTriggerResponse)
async def trigger_workflow(
    workflow_id: str,
    background_tasks: BackgroundTasks,
    triggered_by: Optional[str] = Query(default="manual"),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Workflow).where(Workflow.id == UUID(workflow_id)))
    wf = result.scalar_one_or_none()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    if not wf.is_active:
        raise HTTPException(status_code=409, detail="Workflow is not active")

    try:
        run = await execute_workflow(UUID(workflow_id), triggered_by or "manual", db)
    except ValueError:
        raise HTTPException(status_code=422, detail="Workflow validation failed")
    except Exception:
        raise HTTPException(status_code=500, detail="Workflow execution failed")

    return WorkflowTriggerResponse(
        run_id=run.id,
        workflow_id=UUID(workflow_id),
        status=run.status,
        message=run.summary or "Workflow executed.",
    )


# ─── Run history ─────────────────────────────────────────────────────────────

@router.get("/{workflow_id}/runs", response_model=list[WorkflowRunRead])
async def list_runs(
    workflow_id: str,
    limit: int = Query(default=20, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(WorkflowRun)
        .where(WorkflowRun.workflow_id == UUID(workflow_id))
        .order_by(desc(WorkflowRun.created_at))
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{workflow_id}/runs/{run_id}", response_model=WorkflowRunRead)
async def get_run(workflow_id: str, run_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(WorkflowRun)
        .where(
            WorkflowRun.workflow_id == UUID(workflow_id),
            WorkflowRun.id == UUID(run_id),
        )
    )
    run = result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


# ─── Flight Recorder / Run Replay ────────────────────────────────────────────

@router.get("/{workflow_id}/runs/{run_id}/replay")
async def replay_run(workflow_id: str, run_id: str, db: AsyncSession = Depends(get_db)):
    """
    Flight Recorder — structured replay of a workflow run.
    Returns the full execution timeline: every step, its input/output,
    timing, policy decisions, data sources, and context state.
    """
    # Load workflow
    wf_result = await db.execute(select(Workflow).where(Workflow.id == UUID(workflow_id)))
    wf = wf_result.scalar_one_or_none()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Load run
    run_result = await db.execute(
        select(WorkflowRun).where(
            WorkflowRun.workflow_id == UUID(workflow_id),
            WorkflowRun.id == UUID(run_id),
        )
    )
    run = run_result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    # Parse steps
    try:
        steps_def = json.loads(wf.steps_json or "[]")
    except Exception:
        steps_def = []

    try:
        steps_log = json.loads(run.steps_log or "[]")
    except Exception:
        steps_log = []

    # Build step index from definition
    step_def_map = {s.get("id", f"step-{i}"): s for i, s in enumerate(steps_def)}

    # Build replay timeline
    timeline = []
    for i, log_entry in enumerate(steps_log):
        step_id = log_entry.get("step_id", f"step-{i+1}")
        step_def = step_def_map.get(step_id, {})
        config   = step_def.get("config", {})

        # Timing
        started   = log_entry.get("started_at")
        completed = log_entry.get("completed_at")
        duration_ms = None
        if started and completed:
            try:
                from datetime import datetime as _dt
                s = _dt.fromisoformat(started.replace("Z", "+00:00"))
                c = _dt.fromisoformat(completed.replace("Z", "+00:00"))
                duration_ms = int((c - s).total_seconds() * 1000)
            except Exception:
                pass

        # Enrich agent info if this was an agent_run step
        agent_info = None
        if log_entry.get("type") == "agent_run" or step_def.get("type") == "agent_run":
            agent_id = config.get("agent_id") or step_def.get("agent_id")
            if agent_id:
                from app.models.agent import Agent
                ag_result = await db.execute(
                    select(Agent).where(Agent.id == UUID(str(agent_id)))
                )
                ag = ag_result.scalar_one_or_none()
                if ag:
                    agent_info = {
                        "id": str(ag.id), "name": ag.name, "claw": ag.claw,
                        "risk_level": ag.risk_level, "execution_mode": ag.execution_mode,
                    }

        timeline.append({
            "index":        i + 1,
            "step_id":      step_id,
            "name":         log_entry.get("name") or step_def.get("name") or f"Step {i+1}",
            "type":         log_entry.get("type") or step_def.get("type") or "unknown",
            "status":       log_entry.get("status", "unknown"),
            "output":       log_entry.get("output", ""),
            "started_at":   started,
            "completed_at": completed,
            "duration_ms":  duration_ms,
            "on_failure":   step_def.get("on_failure", "stop"),
            "config":       config,
            "agent_info":   agent_info,
            "data_source":  log_entry.get("data_source"),
            "agent_name":   log_entry.get("agent_name"),
            "agent_claw":   log_entry.get("agent_claw"),
            "event_id":     log_entry.get("event_id"),
            "alerts_routed": log_entry.get("alerts_routed", 0),
        })

    # Step counts
    completed_count = sum(1 for s in timeline if s["status"] == "completed")
    failed_count    = sum(1 for s in timeline if s["status"] == "failed")
    skipped_count   = sum(1 for s in timeline if s["status"] == "skipped")

    return {
        "workflow": {
            "id":          str(wf.id),
            "name":        wf.name,
            "description": wf.description,
            "category":    wf.category,
        },
        "run": {
            "id":              str(run.id),
            "status":          run.status,
            "triggered_by":    run.triggered_by,
            "started_at":      run.started_at,
            "completed_at":    run.completed_at,
            "duration_sec":    run.duration_sec,
            "summary":         run.summary,
            "steps_completed": run.steps_completed,
            "steps_failed":    run.steps_failed,
        },
        "timeline":        timeline,
        "step_count":      len(timeline),
        "completed_count": completed_count,
        "failed_count":    failed_count,
        "skipped_count":   skipped_count,
        "success_rate":    round(completed_count / len(timeline) * 100, 1) if timeline else 0,
    }


@router.get("/runs/{run_id}/replay")
async def replay_run_by_id(run_id: str, db: AsyncSession = Depends(get_db)):
    """Shortcut: replay a run by run_id alone (no workflow_id needed)."""
    run_result = await db.execute(select(WorkflowRun).where(WorkflowRun.id == UUID(run_id)))
    run = run_result.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return await replay_run(str(run.workflow_id), run_id, db)


@router.get("/run-replay/{run_id}")
async def replay_run_by_id_alias(run_id: str, db: AsyncSession = Depends(get_db)):
    """Stable alias for replay-by-run-id to avoid dynamic route shadowing."""
    return await replay_run_by_id(run_id, db)


@router.get("/runs/recent")
async def list_recent_runs(limit: int = Query(default=20, le=100), db: AsyncSession = Depends(get_db)):
    """List the most recent workflow runs across all workflows."""
    result = await db.execute(
        select(WorkflowRun).order_by(desc(WorkflowRun.created_at)).limit(limit)
    )
    runs = result.scalars().all()

    # Enrich with workflow name
    enriched = []
    wf_cache: dict = {}
    for run in runs:
        wf_id = str(run.workflow_id)
        if wf_id not in wf_cache:
            wf_r = await db.execute(select(Workflow).where(Workflow.id == run.workflow_id))
            wf_obj = wf_r.scalar_one_or_none()
            wf_cache[wf_id] = wf_obj.name if wf_obj else None
        if wf_cache[wf_id] is None:
            continue
        enriched.append({
            "run_id":        str(run.id),
            "workflow_id":   wf_id,
            "workflow_name": wf_cache[wf_id],
            "status":        run.status,
            "triggered_by":  run.triggered_by,
            "started_at":    run.started_at,
            "completed_at":  run.completed_at,
            "duration_sec":  run.duration_sec,
            "steps_completed": run.steps_completed,
            "steps_failed":  run.steps_failed,
            "summary":       run.summary,
        })
    return enriched
