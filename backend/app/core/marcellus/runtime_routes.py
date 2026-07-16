from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.marcellus.plexus import (
    acknowledge_plexus_message,
    approve_plexus_message,
    create_plexus_message,
    get_plexus_message,
    list_plexus_messages,
)
from app.core.marcellus.reflexes import (
    approve_reflex_execution,
    create_reflex_definition,
    evaluate_reflex_event,
    get_reflex_execution,
    list_reflex_definitions,
    list_reflex_executions,
)
from app.core.marcellus.regeneration import (
    approve_regeneration,
    create_checkpoint,
    get_regeneration_run,
    list_checkpoints,
    list_node_runtimes,
    list_regeneration_runs,
    start_regeneration,
    verify_checkpoint,
)
from app.core.marcellus.runtime_schemas import (
    CapabilityNodeRuntimeRead,
    CheckpointVerification,
    NodeCheckpointCreate,
    NodeCheckpointRead,
    PlexusAcknowledge,
    PlexusMessageCreate,
    PlexusMessageRead,
    ReflexDefinitionCreate,
    ReflexDefinitionRead,
    ReflexEvent,
    ReflexExecutionRead,
    RegenerationRunRead,
    RegenerationStart,
    TenantAction,
)
from app.core.marcellus.runtime_security import (
    actor_id,
    actor_name,
    require_approver,
    require_message_participant_or_admin,
    require_node_or_admin,
    require_runtime_operator,
    resolve_tenant,
)


router = APIRouter(prefix="/marcellus", tags=["Enkstein Runtime"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/plexus/messages", response_model=PlexusMessageRead, summary="Send a governed peer message")
async def send_plexus_message(
    payload: PlexusMessageCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    require_node_or_admin(user, payload.sender_node_id)
    return await create_plexus_message(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        created_by=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/plexus/messages", response_model=list[PlexusMessageRead], summary="List tenant Plexus messages")
async def plexus_messages(
    tenant_id: str = Query(min_length=1, max_length=128),
    node_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_plexus_messages(db, tenant_id, node_id=node_id, limit=limit)


@router.get("/plexus/inbox/{node_id}", response_model=list[PlexusMessageRead], summary="Pull a Capability Node inbox")
async def plexus_inbox(
    node_id: str,
    tenant_id: str = Query(min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    require_node_or_admin(user, node_id)
    return await list_plexus_messages(db, tenant_id, node_id=node_id, inbox_only=True, limit=limit)


@router.get("/plexus/messages/{message_id}", response_model=PlexusMessageRead, summary="Read and verify message metadata")
async def plexus_message(
    message_id: UUID,
    tenant_id: str = Query(min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    message = await get_plexus_message(db, tenant_id, message_id, include_payload=False)
    require_message_participant_or_admin(user, message.sender_node_id, message.recipient_node_id)
    return await get_plexus_message(db, tenant_id, message_id)


@router.post("/plexus/messages/{message_id}/approve", response_model=PlexusMessageRead, summary="Approve a held peer message")
async def approve_plexus(
    message_id: UUID,
    payload: TenantAction,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    message = await get_plexus_message(db, tenant_id, message_id, include_payload=False)
    approver = require_approver(user, message.created_by)
    return await approve_plexus_message(
        db,
        tenant_id,
        message_id,
        approver=approver,
        approver_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post("/plexus/messages/{message_id}/ack", response_model=PlexusMessageRead, summary="Verify and acknowledge a peer message")
async def acknowledge_plexus(
    message_id: UUID,
    payload: PlexusAcknowledge,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    require_node_or_admin(user, payload.recipient_node_id)
    return await acknowledge_plexus_message(db, tenant_id, message_id, payload.recipient_node_id)


@router.post("/reflexes", response_model=ReflexDefinitionRead, summary="Register a policy-bounded Reflex")
async def register_reflex(
    payload: ReflexDefinitionCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    require_node_or_admin(user, payload.node_id)
    return await create_reflex_definition(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        owner_id=actor_id(user),
        owner_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/reflexes", response_model=list[ReflexDefinitionRead], summary="List Reflex definitions")
async def reflex_definitions(
    tenant_id: str = Query(min_length=1, max_length=128),
    active_only: bool = False,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_reflex_definitions(db, tenant_id, active_only=active_only)


@router.post("/reflexes/evaluate", response_model=list[ReflexExecutionRead], summary="Evaluate an event against local Reflexes")
async def evaluate_reflexes(
    payload: ReflexEvent,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    require_runtime_operator(user)
    return await evaluate_reflex_event(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        requested_by=actor_id(user),
        ip_address=_ip(request),
    )


@router.get("/reflexes/executions", response_model=list[ReflexExecutionRead], summary="List Reflex execution decisions")
async def reflex_executions(
    tenant_id: str = Query(min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_reflex_executions(db, tenant_id, limit=limit)


@router.post(
    "/reflexes/executions/{execution_id}/approve",
    response_model=ReflexExecutionRead,
    summary="Approve a held Reflex execution",
)
async def approve_reflex(
    execution_id: UUID,
    payload: TenantAction,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    execution = await get_reflex_execution(db, tenant_id, execution_id)
    approver = require_approver(user, execution.requested_by)
    return await approve_reflex_execution(
        db,
        tenant_id,
        execution_id,
        approver=approver,
        approver_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post("/regeneration/checkpoints", response_model=NodeCheckpointRead, summary="Create a signed Node checkpoint")
async def checkpoint_node(
    payload: NodeCheckpointCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    require_node_or_admin(user, payload.node_id)
    return await create_checkpoint(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        created_by=actor_id(user),
        created_by_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/regeneration/checkpoints", response_model=list[NodeCheckpointRead], summary="List signed Node checkpoints")
async def checkpoints(
    tenant_id: str = Query(min_length=1, max_length=128),
    node_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_checkpoints(db, tenant_id, node_id=node_id, limit=limit)


@router.post(
    "/regeneration/checkpoints/{checkpoint_id}/verify",
    response_model=CheckpointVerification,
    summary="Verify checkpoint signature and integrity",
)
async def verify_node_checkpoint(
    checkpoint_id: UUID,
    payload: TenantAction,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await verify_checkpoint(db, tenant_id, checkpoint_id)


@router.post("/regeneration/runs", response_model=RegenerationRunRead, summary="Start a governed Regeneration run")
async def regenerate_node(
    payload: RegenerationStart,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    require_runtime_operator(user)
    return await start_regeneration(
        db,
        tenant_id,
        payload.checkpoint_id,
        requested_by=actor_id(user),
        requested_by_name=actor_name(user),
        caller_role=str(user.get("role") or "viewer"),
        ip_address=_ip(request),
    )


@router.post(
    "/regeneration/runs/{run_id}/approve",
    response_model=RegenerationRunRead,
    summary="Approve and execute a Regeneration run",
)
async def approve_regeneration_run(
    run_id: UUID,
    payload: TenantAction,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    run = await get_regeneration_run(db, tenant_id, run_id)
    approver = require_approver(user, run.requested_by)
    return await approve_regeneration(
        db,
        tenant_id,
        run_id,
        approver=approver,
        approver_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/regeneration/runs", response_model=list[RegenerationRunRead], summary="List Regeneration runs")
async def regeneration_runs(
    tenant_id: str = Query(min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_regeneration_runs(db, tenant_id, limit=limit)


@router.get(
    "/regeneration/runtimes",
    response_model=list[CapabilityNodeRuntimeRead],
    summary="List regenerated Capability Node runtimes",
)
async def node_runtimes(
    tenant_id: str = Query(min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_node_runtimes(db, tenant_id)
