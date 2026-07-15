from __future__ import annotations

import json
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.marcellus.runtime_security import actor_id, actor_name, resolve_tenant
from app.core.marcellus.research import TOOLS, invoke_tool, run_research
from app.core.marcellus.workspace import (
    archive_conversation,
    branch_conversation,
    connect_native_workspace,
    create_conversation,
    create_project,
    create_security_investigation,
    delete_artifact,
    execute_turn,
    get_artifact,
    get_conversation_detail,
    ingest_artifacts,
    list_artifacts,
    list_change_proposals,
    list_conversations,
    list_projects,
    move_conversation,
    native_workspace_status,
    review_change_proposal,
    search_workspace,
    sync_native_workspace,
    update_artifact,
    workspace_summary,
)
from app.core.marcellus.workspace_schemas import (
    CortexArtifactBatchCreate,
    CortexArtifactRead,
    CortexArtifactUpdate,
    CortexChangeProposalRead,
    CortexChangeReview,
    CortexBranchCreate,
    CortexConversationCreate,
    CortexConversationDetail,
    CortexConversationMove,
    CortexConversationRead,
    CortexNativeWorkspaceBind,
    CortexNativeWorkspaceRead,
    CortexProjectCreate,
    CortexProjectRead,
    CortexResearchCreate,
    CortexResearchRead,
    CortexSearchResult,
    CortexSecurityInvestigationCreate,
    CortexSecurityInvestigationRead,
    CortexTurnCreate,
    CortexTurnRead,
    CortexToolInvoke,
    CortexToolRead,
    CortexToolResult,
    CortexWorkspaceSummary,
)
from app.core.swarm.orchestrator import run_swarm_job


router = APIRouter(prefix="/marcellus/workspace", tags=["Marcellus Workspace"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(jsonable_encoder(payload), separators=(',', ':'))}\n\n"


@router.get("/tools", response_model=list[CortexToolRead], summary="List governed Cowork MCP tools")
async def get_workspace_tools(user: dict = Depends(get_current_user)):
    return TOOLS


@router.post("/tools/invoke", response_model=CortexToolResult, summary="Invoke an allowlisted Cowork MCP tool")
async def post_workspace_tool(
    payload: CortexToolInvoke,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await invoke_tool(
        db,
        tenant_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post("/projects", response_model=CortexProjectRead, summary="Create an encrypted Cortex project")
async def post_project(
    payload: CortexProjectCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await create_project(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/projects", response_model=list[CortexProjectRead], summary="List accessible Cortex projects")
async def get_projects(
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_projects(db, tenant_id, user=user, owner_id=actor_id(user))


@router.post(
    "/projects/{project_id}/research",
    response_model=CortexResearchRead,
    summary="Research public sources and persist a cited Cowork report",
)
async def post_project_research(
    project_id: UUID,
    payload: CortexResearchCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await run_research(
        db,
        tenant_id,
        project_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/projects/{project_id}/native-workspace",
    response_model=CortexNativeWorkspaceRead,
    summary="Connect a desktop-approved local folder",
)
async def post_native_workspace(
    project_id: UUID,
    payload: CortexNativeWorkspaceBind,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await connect_native_workspace(
        db, tenant_id, project_id, payload.model_copy(update={"tenant_id": tenant_id}),
        user=user, actor_id=actor_id(user), actor_name=actor_name(user), ip_address=_ip(request),
    )


@router.get(
    "/projects/{project_id}/native-workspace",
    response_model=CortexNativeWorkspaceRead,
    summary="Read local folder connection status",
)
async def get_native_workspace(
    project_id: UUID,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await native_workspace_status(db, tenant_id, project_id, user=user)


@router.post(
    "/projects/{project_id}/native-workspace/sync",
    response_model=CortexNativeWorkspaceRead,
    summary="Sync a connected local folder",
)
async def post_native_workspace_sync(
    project_id: UUID,
    request: Request,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await sync_native_workspace(
        db, tenant_id, project_id,
        user=user, actor_id=actor_id(user), actor_name=actor_name(user), ip_address=_ip(request),
    )


@router.post("/conversations", response_model=CortexConversationRead, summary="Create a persistent conversation")
async def post_conversation(
    payload: CortexConversationCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await create_conversation(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/conversations", response_model=list[CortexConversationRead], summary="List persistent conversations")
async def get_conversations(
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    project_id: UUID | None = None,
    mode: str | None = Query(default=None, pattern="^(chat|cowork|security)$"),
    include_archived: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_conversations(
        db,
        tenant_id,
        user=user,
        owner_id=actor_id(user),
        project_id=project_id,
        mode=mode,
        include_archived=include_archived,
        limit=limit,
    )


@router.get(
    "/conversations/{conversation_id}",
    response_model=CortexConversationDetail,
    summary="Read an encrypted conversation",
)
async def get_conversation(
    conversation_id: UUID,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await get_conversation_detail(db, tenant_id, conversation_id, user=user)


@router.delete(
    "/conversations/{conversation_id}",
    response_model=CortexConversationRead,
    summary="Archive a conversation",
)
async def delete_conversation(
    conversation_id: UUID,
    request: Request,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await archive_conversation(
        db,
        tenant_id,
        conversation_id,
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/conversations/{conversation_id}/move",
    response_model=CortexConversationRead,
    summary="Move a conversation into a Cowork project",
)
async def post_conversation_move(
    conversation_id: UUID,
    payload: CortexConversationMove,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await move_conversation(
        db,
        tenant_id,
        conversation_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/conversations/{conversation_id}/turns",
    response_model=CortexTurnRead,
    summary="Execute and persist a governed Cortex turn",
)
async def post_turn(
    conversation_id: UUID,
    payload: CortexTurnCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await execute_turn(
        db,
        tenant_id,
        conversation_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
    )


@router.post(
    "/conversations/{conversation_id}/turns/stream",
    summary="Stream a governed Cortex turn",
)
async def post_turn_stream(
    conversation_id: UUID,
    payload: CortexTurnCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    trusted_payload = payload.model_copy(update={"tenant_id": tenant_id})

    async def events():
        yield _sse("turn_started", {"conversation_id": conversation_id, "agent_mode": trusted_payload.agent_mode})
        yield _sse("context_ready", {"artifact_count": len(trusted_payload.artifact_ids), "include_project_files": trusted_payload.include_project_files})
        try:
            turn = await execute_turn(
                db,
                tenant_id,
                conversation_id,
                trusted_payload,
                user=user,
                actor_id=actor_id(user),
            )
        except Exception:
            await db.rollback()
            yield _sse("turn_failed", {"detail": "The governed turn could not be completed."})
            return
        for vote in turn.gateway.get("votes", []):
            yield _sse(
                "brain_completed",
                {
                    key: vote.get(key)
                    for key in ("source", "provider", "model", "counted", "reason", "latency_ms", "policy_outcome")
                },
            )
        content = turn.assistant_message.content if turn.assistant_message else ""
        for offset in range(0, len(content), 96):
            yield _sse("response_delta", {"delta": content[offset : offset + 96]})
        proposal_ids = (turn.assistant_message.governance if turn.assistant_message else {}).get("change_proposal_ids", [])
        if proposal_ids:
            yield _sse("changes_proposed", {"proposal_ids": proposal_ids, "count": len(proposal_ids)})
        yield _sse("turn_completed", turn.model_dump(mode="json"))

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post(
    "/conversations/{conversation_id}/branches",
    response_model=CortexConversationDetail,
    summary="Branch a conversation at a message",
)
async def post_branch(
    conversation_id: UUID,
    payload: CortexBranchCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await branch_conversation(
        db,
        tenant_id,
        conversation_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
    )


@router.post(
    "/conversations/{conversation_id}/security-investigation",
    response_model=CortexSecurityInvestigationRead,
    summary="Create a governed Security Swarm from Cortex context",
)
async def post_security_investigation(
    conversation_id: UUID,
    payload: CortexSecurityInvestigationCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    result = await create_security_investigation(
        db,
        tenant_id,
        conversation_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )
    if not result.requires_approval:
        background_tasks.add_task(run_swarm_job, result.job_id)
    return result


@router.post("/artifacts", response_model=list[CortexArtifactRead], summary="Ingest encrypted project artifacts")
async def post_artifacts(
    payload: CortexArtifactBatchCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await ingest_artifacts(
        db,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get(
    "/projects/{project_id}/artifacts",
    response_model=list[CortexArtifactRead],
    summary="List project artifacts",
)
async def get_artifacts(
    project_id: UUID,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    include_versions: bool = False,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_artifacts(db, tenant_id, project_id, user=user, include_versions=include_versions)


@router.get(
    "/projects/{project_id}/change-proposals",
    response_model=list[CortexChangeProposalRead],
    summary="List pending governed file changes",
)
async def get_change_proposals(
    project_id: UUID,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_change_proposals(db, tenant_id, project_id, user=user)


@router.post(
    "/change-proposals/{proposal_id}/review",
    response_model=CortexChangeProposalRead,
    summary="Approve or reject a governed file change",
)
async def post_change_proposal_review(
    proposal_id: UUID,
    payload: CortexChangeReview,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await review_change_proposal(
        db,
        tenant_id,
        proposal_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/artifacts/{artifact_id}", response_model=CortexArtifactRead, summary="Read a project artifact")
async def get_artifact_content(
    artifact_id: UUID,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await get_artifact(db, tenant_id, artifact_id, user=user)


@router.patch("/artifacts/{artifact_id}", response_model=CortexArtifactRead, summary="Edit or move a project artifact")
async def patch_artifact_content(
    artifact_id: UUID,
    payload: CortexArtifactUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await update_artifact(
        db, tenant_id, artifact_id, payload.model_copy(update={"tenant_id": tenant_id}),
        user=user, actor_id=actor_id(user), actor_name=actor_name(user), ip_address=_ip(request),
    )


@router.delete("/artifacts/{artifact_id}", response_model=CortexArtifactRead, summary="Move a project artifact to recoverable trash")
async def delete_artifact_content(
    artifact_id: UUID,
    request: Request,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await delete_artifact(
        db,
        tenant_id,
        artifact_id,
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get("/search", response_model=list[CortexSearchResult], summary="Search accessible conversation history")
async def search_conversations(
    q: str = Query(min_length=2, max_length=200),
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    limit: int = Query(default=50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await search_workspace(db, tenant_id, q, user=user, owner_id=actor_id(user), limit=limit)


@router.get("/summary", response_model=CortexWorkspaceSummary, summary="Workspace activity summary")
async def get_workspace_summary(
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await workspace_summary(db, tenant_id, user=user, owner_id=actor_id(user))
