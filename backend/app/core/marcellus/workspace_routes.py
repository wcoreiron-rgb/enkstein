from __future__ import annotations

import asyncio
import json
import time
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.marcellus.runtime_security import actor_id, actor_name, resolve_tenant
from app.core.marcellus.ai_rate_limit import enforce_ai_rate_limit
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
    permanently_delete_conversation,
    rename_conversation,
    reopen_conversation,
    review_change_proposal,
    search_workspace,
    sync_native_workspace,
    update_artifact,
    workspace_summary,
)
from app.core.marcellus.codex_workspace import (
    codex_approval,
    codex_cancel,
    codex_start,
    codex_status,
    codex_turn,
)
from app.core.marcellus.workspace_schemas import (
    CortexArtifactBatchCreate,
    CortexCodexApproval,
    CortexCodexApprovalRead,
    CortexCodexCancel,
    CortexCodexCancelRead,
    CortexCodexStart,
    CortexCodexStartRead,
    CortexCodexStatusRead,
    CortexCodexTurn,
    CortexCodexTurnRead,
    CortexArtifactRead,
    CortexArtifactUpdate,
    CortexChangeProposalRead,
    CortexChangeReview,
    CortexBranchCreate,
    CortexConversationCreate,
    CortexConversationDeleteRead,
    CortexConversationDetail,
    CortexConversationMove,
    CortexConversationRead,
    CortexConversationRename,
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


router = APIRouter(prefix="/marcellus/workspace", tags=["Enkstein Workspace"])


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _sse(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(jsonable_encoder(payload), separators=(',', ':'))}\n\n"


# Bounded chunk size for streamed assistant deltas. Small enough that the first
# visible token arrives promptly and a single frame can never balloon the wire,
# large enough to avoid per-character frame overhead on long scripts.
_STREAM_CHUNK_CHARS = 96


def _turn_content_frames(turn):
    """Yield the ordered content/governance SSE frames for a completed turn.

    Emitted only after ``execute_turn`` has resolved, so the full permitted
    assistant output is already persisted encrypted; the deltas here are a
    presentation re-chunking of that persisted content and carry no state the
    client cannot recover from the terminal ``turn_completed`` payload.
    """
    governance = (turn.assistant_message.governance if turn.assistant_message else {}) or {}
    yield _sse("context_ready", {"context_manifest": governance.get("context_manifest")})
    for vote in turn.gateway.get("votes", []):
        yield _sse(
            "brain_completed",
            {
                key: vote.get(key)
                for key in ("source", "provider", "model", "counted", "reason", "latency_ms", "policy_outcome")
            },
        )
    content = turn.assistant_message.content if turn.assistant_message else ""
    for offset in range(0, len(content), _STREAM_CHUNK_CHARS):
        yield _sse("response_delta", {"delta": content[offset : offset + _STREAM_CHUNK_CHARS]})
    proposal_ids = governance.get("change_proposal_ids", [])
    if proposal_ids:
        yield _sse(
            "changes_proposed",
            {
                "proposal_ids": proposal_ids,
                "count": len(proposal_ids),
                "changes": governance.get("file_changes", []),
            },
        )
    applied_paths = governance.get("applied_change_paths", [])
    if applied_paths:
        yield _sse(
            "changes_applied",
            {
                "paths": applied_paths,
                "count": len(applied_paths),
                "changes": governance.get("file_changes", []),
            },
        )
    yield _sse("turn_completed", turn.model_dump(mode="json"))


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
    kind: str | None = Query(default=None, pattern="^(cowork|chat)$"),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await list_projects(db, tenant_id, user=user, owner_id=actor_id(user), kind=kind)


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
    # Research fans out to fetches plus a synthesis Brain call.
    enforce_ai_rate_limit(actor_id(user))
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


@router.delete(
    "/conversations/{conversation_id}/permanent",
    response_model=CortexConversationDeleteRead,
    summary="Permanently delete a conversation and its dependent conversation-scoped data",
)
async def delete_conversation_permanent(
    conversation_id: UUID,
    request: Request,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await permanently_delete_conversation(
        db,
        tenant_id,
        conversation_id,
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/conversations/{conversation_id}/reopen",
    response_model=CortexConversationRead,
    summary="Reopen an archived conversation",
)
async def post_conversation_reopen(
    conversation_id: UUID,
    request: Request,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await reopen_conversation(
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
    "/conversations/{conversation_id}/rename",
    response_model=CortexConversationRead,
    summary="Rename a conversation",
)
async def post_conversation_rename(
    conversation_id: UUID,
    payload: CortexConversationRename,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await rename_conversation(
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
    enforce_ai_rate_limit(actor_id(user))
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
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    enforce_ai_rate_limit(actor_id(user))
    trusted_payload = payload.model_copy(update={"tenant_id": tenant_id})
    # A small positive floor prevents a misconfigured 0/negative interval from
    # busy-looping; the deadline can never be shorter than one heartbeat.
    heartbeat = max(0.05, float(settings.WORKSPACE_STREAM_HEARTBEAT_SECONDS))
    # A Browser Companion session runs at human/page speed and can
    # legitimately take longer than the default deadline to produce a full
    # response (see _BROWSER_BRAIN_TIMEOUT_SECONDS in brain_bridge.py, which
    # this stays comfortably above). When any requested source is a browser
    # session -- either directly or as part of a consensus/swarm request --
    # the turn gets the longer budget instead of silently being cancelled
    # while the browser tab is still legitimately generating.
    requested_sources = trusted_payload.consensus_sources or [trusted_payload.source or ""]
    includes_browser_source = any(str(item).endswith("_browser") for item in requested_sources)
    deadline_setting = (
        settings.WORKSPACE_STREAM_BROWSER_DEADLINE_SECONDS
        if includes_browser_source
        else settings.WORKSPACE_STREAM_DEADLINE_SECONDS
    )
    deadline = max(heartbeat, float(deadline_setting))

    async def events():
        yield _sse(
            "turn_started",
            {"conversation_id": conversation_id, "agent_mode": trusted_payload.agent_mode},
        )
        # Real intermediate Brain lifecycle events (currently only emitted for browser
        # sources) are pushed here from within the background turn task as they happen,
        # and drained below alongside the existing heartbeat loop so they reach the wire
        # promptly instead of waiting for the turn to fully resolve.
        progress_queue: asyncio.Queue[tuple[str, str, str | None]] = asyncio.Queue()
        file_progress_queue: asyncio.Queue[tuple[str, str, str]] = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def on_progress(source: str, state: str, label: str | None) -> None:
            # invoke_subscription_brain calls this synchronously from inside an async
            # context already on this loop, so put_nowait is safe here (never called
            # from a different thread/loop).
            loop.call_soon_threadsafe(progress_queue.put_nowait, (source, state, label))

        def on_file_progress(path: str, operation: str, outcome: str) -> None:
            loop.call_soon_threadsafe(file_progress_queue.put_nowait, (path, operation, outcome))

        # Watches for a real ASGI http.disconnect message exactly once, in its own
        # task, for the entire life of the stream. request.is_disconnected() calls
        # request._receive() internally; calling it repeatedly from a polling loop
        # (as this endpoint previously did, once per heartbeat) competes with
        # uvicorn's own use of the same ASGI receive channel and is a documented
        # false-positive source on long-lived streaming responses -- a multi-minute
        # browser Brain turn could have its request wrongly treated as disconnected
        # partway through, silently cancelling and rolling back a turn that was
        # still genuinely in progress (the Brain itself would go on to complete
        # normally, orphaned, with no live request left to receive its answer).
        # Reading the receive channel exactly once here, from a single dedicated
        # task, avoids that contention entirely.
        disconnected = asyncio.Event()

        async def watch_disconnect() -> None:
            try:
                while True:
                    message = await request.receive()
                    if message.get("type") == "http.disconnect":
                        disconnected.set()
                        return
            except asyncio.CancelledError:
                pass

        disconnect_watcher = asyncio.ensure_future(watch_disconnect())

        # Run the governed turn as a supervised task so the request coroutine can
        # keep the wire warm with heartbeats and enforce a hard deadline. The turn
        # is executed exactly once; the terminal event (completed/failed/timeout)
        # is emitted exactly once and the stream then closes — it never hangs.
        task = asyncio.ensure_future(
            execute_turn(
                db,
                tenant_id,
                conversation_id,
                trusted_payload,
                user=user,
                actor_id=actor_id(user),
                on_progress=on_progress,
                on_file_progress=on_file_progress,
            )
        )
        started = time.monotonic()
        try:
            while True:
                while not progress_queue.empty():
                    source, state, label = progress_queue.get_nowait()
                    yield _sse("brain_progress", {"source": source, "state": state, "label": label})
                while not file_progress_queue.empty():
                    path, operation, outcome = file_progress_queue.get_nowait()
                    yield _sse("file_progress", {"path": path, "operation": operation, "outcome": outcome})
                await asyncio.wait({task}, timeout=heartbeat)
                if task.done():
                    break
                elapsed = time.monotonic() - started
                # If the client has gone away, stop the governed work and release
                # the transaction rather than streaming into a dead socket.
                if disconnected.is_set():
                    task.cancel()
                    try:
                        await task
                    except BaseException:  # noqa: BLE001 - cancellation/teardown
                        pass
                    await db.rollback()
                    disconnect_watcher.cancel()
                    return
                if elapsed >= deadline:
                    # Hard bound reached: cancel the stalled turn, roll back, and
                    # deliver a terminal state so the client never streams forever.
                    task.cancel()
                    try:
                        await task
                    except BaseException:  # noqa: BLE001 - cancellation/teardown
                        pass
                    await db.rollback()
                    disconnect_watcher.cancel()
                    yield _sse(
                        "turn_timeout",
                        {
                            "detail": "The governed turn exceeded the streaming deadline and was stopped.",
                            "elapsed_ms": int(elapsed * 1000),
                        },
                    )
                    return
                yield _sse("heartbeat", {"elapsed_ms": int(elapsed * 1000)})
        except asyncio.CancelledError:
            # The server is tearing down the response (client disconnect at the
            # transport layer): abandon the turn without leaving it running.
            task.cancel()
            disconnect_watcher.cancel()
            raise

        disconnect_watcher.cancel()

        while not progress_queue.empty():
            source, state, label = progress_queue.get_nowait()
            yield _sse("brain_progress", {"source": source, "state": state, "label": label})
        while not file_progress_queue.empty():
            path, operation, outcome = file_progress_queue.get_nowait()
            yield _sse("file_progress", {"path": path, "operation": operation, "outcome": outcome})

        try:
            turn = task.result()
        except asyncio.CancelledError:
            await db.rollback()
            yield _sse("turn_failed", {"detail": "The governed turn was cancelled."})
            return
        except Exception:
            await db.rollback()
            yield _sse("turn_failed", {"detail": "The governed turn could not be completed."})
            return

        for frame in _turn_content_frames(turn):
            yield frame

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post(
    "/conversations/{conversation_id}/codex/start",
    response_model=CortexCodexStartRead,
    summary="Open or resume the governed Codex App Server thread",
)
async def post_codex_start(
    conversation_id: UUID,
    payload: CortexCodexStart,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await codex_start(
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
    "/conversations/{conversation_id}/codex/turn",
    response_model=CortexCodexTurnRead,
    summary="Send a governed Codex App Server turn",
)
async def post_codex_turn(
    conversation_id: UUID,
    payload: CortexCodexTurn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await codex_turn(
        db,
        tenant_id,
        conversation_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.get(
    "/conversations/{conversation_id}/codex/status",
    response_model=CortexCodexStatusRead,
    summary="Read bounded Codex App Server session status",
)
async def get_codex_status(
    conversation_id: UUID,
    request: Request,
    tenant_id: str = Query(default="global", min_length=1, max_length=128),
    cursor: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, tenant_id)
    return await codex_status(
        db,
        tenant_id,
        conversation_id,
        cursor,
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/conversations/{conversation_id}/codex/approvals/{approval_id}",
    response_model=CortexCodexApprovalRead,
    summary="Govern a pending Codex App Server approval",
)
async def post_codex_approval(
    conversation_id: UUID,
    payload: CortexCodexApproval,
    request: Request,
    approval_id: str = Path(min_length=1, max_length=64, pattern=r"^apr-[A-Za-z0-9-]{1,60}$"),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await codex_approval(
        db,
        tenant_id,
        conversation_id,
        approval_id,
        payload.model_copy(update={"tenant_id": tenant_id}),
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/conversations/{conversation_id}/codex/cancel",
    response_model=CortexCodexCancelRead,
    summary="Cancel the active Codex App Server turn",
)
async def post_codex_cancel(
    conversation_id: UUID,
    payload: CortexCodexCancel,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    tenant_id = resolve_tenant(user, payload.tenant_id)
    return await codex_cancel(
        db,
        tenant_id,
        conversation_id,
        user=user,
        actor_id=actor_id(user),
        actor_name=actor_name(user),
        ip_address=_ip(request),
    )


@router.post(
    "/conversations/{conversation_id}/branches",
    response_model=CortexConversationDetail,
    summary="Branch a conversation at a message",
)
async def post_branch(
    conversation_id: UUID,
    payload: CortexBranchCreate,
    request: Request,
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
        actor_name=actor_name(user),
        ip_address=_ip(request),
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
