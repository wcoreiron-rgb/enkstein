from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.marcellus.mission_schemas import (
    CortexMissionCreate,
    CortexMissionObservationRead,
    CortexMissionObservationReview,
    CortexMissionRead,
    CortexMissionRunRead,
    CortexMissionUpdate,
    CortexOvernightBriefRead,
)
from app.core.marcellus.missions import (
    _get_mission,
    _require_owner,
    create_mission,
    generate_overnight_brief,
    launch_mission,
    list_missions,
    list_observations,
    review_observation,
    run_mission_job,
    update_mission,
)
from app.core.marcellus.runtime_security import actor_id, actor_name, resolve_tenant


router = APIRouter(prefix="/marcellus/missions", tags=["Enkstein Missions"])


@router.post("", response_model=CortexMissionRead, summary="Create a persistent governed Mission")
async def post_mission(
    payload: CortexMissionCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await create_mission(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        owner_id=actor_id(user),
        owner_name=actor_name(user),
    )


@router.get("", response_model=list[CortexMissionRead], summary="List accessible Missions")
async def get_missions(
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_missions(db, tenant_id, user=user, owner_id=actor_id(user))


@router.patch("/{mission_id}", response_model=CortexMissionRead, summary="Pause, resume, or change a Mission")
async def patch_mission(
    mission_id: UUID,
    payload: CortexMissionUpdate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await update_mission(
        db,
        tenant_id,
        mission_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
    )


@router.post("/{mission_id}/run", response_model=CortexMissionRunRead, summary="Run a Mission now")
async def post_mission_run(
    mission_id: UUID,
    background_tasks: BackgroundTasks,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    mission = await _get_mission(db, tenant_id, mission_id)
    _require_owner(user, mission.owner_id)
    result = await launch_mission(
        db,
        mission,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
    )
    background_tasks.add_task(run_mission_job, mission.id, result.job_id)
    return result


@router.get(
    "/memory/observations",
    response_model=list[CortexMissionObservationRead],
    summary="List tenant-scoped Mission memory",
)
async def get_mission_observations(
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    status: str | None = Query(default=None, pattern="^(proposed|approved|rejected|blocked)$"),
    limit: int = Query(default=100, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_observations(
        db,
        tenant_id,
        user=user,
        owner_id=actor_id(user),
        status_filter=status,
        limit=limit,
    )


@router.post(
    "/memory/observations/{observation_id}/review",
    response_model=CortexMissionObservationRead,
    summary="Approve or reject Mission memory",
)
async def post_mission_observation_review(
    observation_id: UUID,
    payload: CortexMissionObservationReview,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await review_observation(
        db,
        tenant_id,
        observation_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_name=actor_name(user),
    )


@router.post("/overnight-brief", response_model=CortexOvernightBriefRead, summary="Generate an encrypted overnight brief")
async def post_overnight_brief(
    hours: int = Query(default=12, ge=1, le=72),
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await generate_overnight_brief(db, tenant_id, user=user, owner_id=actor_id(user), hours=hours)
