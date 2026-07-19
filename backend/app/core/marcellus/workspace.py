from __future__ import annotations

import difflib
import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import desc, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.scanner import scan_text
from app.core.marcellus.context_compiler import (
    ContextManifest,
    UnknownClassification,
    compile_context,
    finalize_context_provenance,
    highest_classification,
)
from app.core.marcellus.crypto import decrypt_json, encrypt_json
from app.core.marcellus.workspace_schemas import (
    CortexArtifactBatchCreate,
    CortexArtifactItem,
    CortexArtifactRead,
    CortexArtifactUpdate,
    CortexBranchCreate,
    CortexConversationCreate,
    CortexConversationDeleteRead,
    CortexConversationDetail,
    CortexConversationMove,
    CortexConversationRead,
    CortexConversationRename,
    CortexChangeProposalRead,
    CortexChangeReview,
    CortexMessageRead,
    CortexNativeProjectPickCreate,
    CortexNativeProjectRead,
    CortexNativeWorkspaceBind,
    CortexNativeWorkspaceRead,
    CortexProjectCreate,
    CortexProjectRead,
    CortexSearchResult,
    CortexSecurityInvestigationCreate,
    CortexSecurityInvestigationRead,
    CortexTurnCreate,
    CortexTurnRead,
    CortexWorkspaceSummary,
)
from app.core.modelclaw.gateway import execute_cortex_gateway
from app.core.marcellus.native_workspace import (
    get_binding,
    list_native_files,
    mirror_rename,
    mirror_trash,
    mirror_write,
    native_files_payload,
    pick_native_root,
    set_binding,
)
from app.core.modelclaw.schemas import CortexGatewayRequest, CortexMessage
from app.core.swarm.orchestrator import create_swarm_job
from app.core.swarm.schemas import SwarmJobCreate
from app.models.marcellus import CortexArtifact, CortexConversation, CortexConversationMessage, CortexProject
from app.models.swarm import SwarmJobStatus
from app.trust_fabric import ActionRequest, enforce
from app.trust_fabric.agt_bridge import audit_prompt


_ADMIN_ROLES = {"admin", "security_admin", "super_admin"}
_SECURITY_HANDOFF_PARTICIPANTS = {
    "arcclaw",
    "threatclaw",
    "identityclaw",
    "cloudclaw",
    "dataclaw",
    "complianceclaw",
    "appclaw",
    "devclaw",
    "endpointclaw",
    "logclaw",
    "netclaw",
    "privacyclaw",
}
_CHANGE_BLOCK = re.compile(r"```marcellus_changes[ \t]*\r?\n(.*?)```", re.IGNORECASE | re.DOTALL)
_CHANGE_MIME = "application/vnd.marcellus.change+json"


def _can_read_all(user: dict[str, Any]) -> bool:
    return str(user.get("role") or "").lower() in _ADMIN_ROLES


def _require_owner(user: dict[str, Any], owner_id: str) -> None:
    actor = str(user.get("sub") or user.get("id") or "")
    if actor != owner_id and not _can_read_all(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Workspace access denied")


def _message_read(message: CortexConversationMessage) -> CortexMessageRead:
    content = decrypt_json(message.content_ciphertext, message.content_digest)["content"]
    try:
        governance = json.loads(message.governance_json or "{}")
    except json.JSONDecodeError:
        governance = {}
    return CortexMessageRead(
        id=message.id,
        tenant_id=message.tenant_id,
        conversation_id=message.conversation_id,
        role=message.role,
        content=content,
        classification=message.classification,
        source=message.source,
        provider=message.provider,
        model=message.model,
        governance=governance,
        parent_message_id=message.parent_message_id,
        created_at=message.created_at,
    )


def _artifact_read(artifact: CortexArtifact, *, include_content: bool = False) -> CortexArtifactRead:
    content = None
    if include_content:
        content = decrypt_json(artifact.content_ciphertext, artifact.content_digest)["content"]
    return CortexArtifactRead(
        id=artifact.id,
        tenant_id=artifact.tenant_id,
        project_id=artifact.project_id,
        conversation_id=artifact.conversation_id,
        path=artifact.path,
        mime_type=artifact.mime_type,
        size_bytes=artifact.size_bytes,
        content_digest=artifact.content_digest,
        classification=artifact.classification,
        version=artifact.version,
        status=artifact.status,
        created_by=artifact.created_by,
        created_at=artifact.created_at,
        content=content,
    )


def _extract_change_requests(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Extract the bounded change protocol without trusting free-form model output."""
    match = _CHANGE_BLOCK.search(text)
    if not match:
        return text, []
    try:
        raw_changes = json.loads(match.group(1))
    except (TypeError, json.JSONDecodeError):
        return text, []
    if not isinstance(raw_changes, list):
        return text, []

    changes: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for raw in raw_changes[:10]:
        if not isinstance(raw, dict) or raw.get("operation") not in {"create", "update", "delete"}:
            continue
        operation = str(raw["operation"])
        content = "" if operation == "delete" else str(raw.get("content") or "")
        try:
            item = CortexArtifactItem(
                path=str(raw.get("path") or ""),
                content=content,
                mime_type=str(raw.get("mime_type") or "text/plain"),
            )
        except Exception:
            continue
        if item.path in seen_paths:
            continue
        seen_paths.add(item.path)
        changes.append(
            {
                "operation": operation,
                "path": item.path,
                "content": item.content,
                "mime_type": item.mime_type,
            }
        )
    cleaned = _CHANGE_BLOCK.sub("", text).strip()
    if changes:
        cleaned = f"{cleaned}\n\nPrepared {len(changes)} governed file change{'s' if len(changes) != 1 else ''} for review.".strip()
    return cleaned or "Prepared governed file changes for review.", changes


def _proposal_read(proposal: CortexArtifact, current: CortexArtifact | None = None) -> CortexChangeProposalRead:
    envelope = decrypt_json(proposal.content_ciphertext, proposal.content_digest)
    current_content = None
    if current is not None:
        current_content = decrypt_json(current.content_ciphertext, current.content_digest)["content"]
    return CortexChangeProposalRead(
        id=proposal.id,
        project_id=proposal.project_id,
        conversation_id=proposal.conversation_id,
        operation=envelope["operation"],
        path=envelope["path"],
        status=proposal.status,
        proposed_content=envelope.get("content") if envelope["operation"] != "delete" else None,
        current_content=current_content,
        base_digest=envelope.get("base_digest"),
        previous_path=envelope.get("previous_path"),
        created_by=proposal.created_by,
        created_at=proposal.created_at,
    )


async def _authorize(
    db: AsyncSession,
    *,
    tenant_id: str,
    actor_id: str,
    actor_name: str,
    action: str,
    target: str,
    target_type: str,
    context: dict[str, Any],
    ip_address: str | None = None,
) -> None:
    decision = await enforce(
        db,
        ActionRequest(
            module="marcellus_workspace",
            actor_id=actor_id,
            actor_name=actor_name,
            actor_type="human",
            action=action,
            target=target,
            target_type=target_type,
            context={**context, "tenant_id": tenant_id},
        ),
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Workspace action denied by {decision.policy_name}",
        )


async def _get_project(db: AsyncSession, tenant_id: str, project_id: uuid.UUID) -> CortexProject:
    result = await db.execute(
        select(CortexProject).where(CortexProject.tenant_id == tenant_id, CortexProject.id == project_id)
    )
    project = result.scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


async def _get_conversation(db: AsyncSession, tenant_id: str, conversation_id: uuid.UUID) -> CortexConversation:
    result = await db.execute(
        select(CortexConversation).where(
            CortexConversation.tenant_id == tenant_id,
            CortexConversation.id == conversation_id,
        )
    )
    conversation = result.scalar_one_or_none()
    if conversation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    return conversation


async def create_project(
    db: AsyncSession,
    payload: CortexProjectCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexProjectRead:
    await _authorize(
        db,
        tenant_id=payload.tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_project_create",
        target=payload.name,
        target_type="cortex_project",
        context={"classification": payload.classification, "default_source": payload.default_source},
        ip_address=ip_address,
    )
    name_scan = scan_text(payload.name.strip(), redact=True)
    description_scan = scan_text(payload.description.strip(), redact=True)
    project = CortexProject(
        tenant_id=payload.tenant_id,
        owner_id=actor_id,
        name=(name_scan.redacted if name_scan.is_sensitive else payload.name.strip())[:255],
        description=(
            description_scan.redacted if description_scan.is_sensitive else payload.description.strip()
        ),
        classification=payload.classification,
        default_source=payload.default_source,
    )
    db.add(project)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A project with this name already exists")
    await db.refresh(project)
    return CortexProjectRead.model_validate(project)


async def connect_native_workspace(
    db: AsyncSession,
    tenant_id: str,
    project_id: uuid.UUID,
    payload: CortexNativeWorkspaceBind,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexNativeWorkspaceRead:
    project = await _get_project(db, tenant_id, project_id)
    _require_owner(user, project.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_native_folder_bind",
        target=str(project.id),
        target_type="cortex_project",
        context={"folder_name": payload.name, "grant_type": "opaque_native_token"},
        ip_address=ip_address,
    )
    set_binding(tenant_id, project.id, token=payload.token, name=payload.name, path_alias=payload.path_alias)
    synced = await _sync_bound_root(
        db, tenant_id, project, user=user, actor_id=actor_id, actor_name=actor_name, ip_address=ip_address
    )
    return CortexNativeWorkspaceRead(
        connected=True,
        name=payload.name,
        path_alias=payload.path_alias,
        file_count=synced["file_count"],
        synced_files=synced["synced_files"],
    )


async def _sync_bound_root(
    db: AsyncSession,
    tenant_id: str,
    project: CortexProject,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> dict[str, int]:
    """Ingest the currently approved root's validated files into the project.

    The host bridge is the authoritative boundary; ingest never mirrors back to
    native so a read-only sync cannot mutate the approved folder.
    """
    files = await list_native_files(tenant_id, project.id)
    created = await ingest_artifacts(
        db,
        native_files_payload(
            tenant_id=tenant_id,
            project_id=project.id,
            files=files,
            classification=project.classification,
        ),
        user=user,
        actor_id=actor_id,
        actor_name=actor_name,
        ip_address=ip_address,
        mirror_to_native=False,
    ) if files else []
    return {"file_count": len(files), "synced_files": len(created)}


async def pick_and_create_native_project(
    db: AsyncSession,
    payload: CortexNativeProjectPickCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexNativeProjectRead:
    """Open the host folder picker and, only on picker success, create a Cowork
    project bound to the approved root, then sync its files.

    ``pick_native_root`` raises before anything is created if the picker is
    cancelled (or returns no opaque token), so cancellation persists nothing.
    Only the opaque token/name/path_alias ever cross the bridge boundary.
    """
    grant = await pick_native_root()
    await _authorize(
        db,
        tenant_id=payload.tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_project_create",
        target=grant["name"],
        target_type="cortex_project",
        context={"classification": payload.classification, "grant_type": "opaque_native_token"},
        ip_address=ip_address,
    )
    await _authorize(
        db,
        tenant_id=payload.tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_native_folder_bind",
        target=grant["name"],
        target_type="cortex_project",
        context={"folder_name": grant["name"], "grant_type": "opaque_native_token"},
        ip_address=ip_address,
    )
    name_scan = scan_text(grant["name"], redact=True)
    project = CortexProject(
        tenant_id=payload.tenant_id,
        owner_id=actor_id,
        name=(name_scan.redacted if name_scan.is_sensitive else grant["name"])[:255],
        description="",
        classification=payload.classification,
        default_source=payload.default_source,
    )
    db.add(project)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A project with this name already exists")
    await db.refresh(project)
    set_binding(
        payload.tenant_id,
        project.id,
        token=grant["token"],
        name=grant["name"],
        path_alias=grant.get("path_alias"),
    )
    synced = await _sync_bound_root(
        db, payload.tenant_id, project, user=user, actor_id=actor_id, actor_name=actor_name, ip_address=ip_address
    )
    return CortexNativeProjectRead(
        project=CortexProjectRead.model_validate(project),
        workspace=CortexNativeWorkspaceRead(
            connected=True,
            name=grant["name"],
            path_alias=grant.get("path_alias"),
            file_count=synced["file_count"],
            synced_files=synced["synced_files"],
        ),
    )


async def native_workspace_status(
    db: AsyncSession, tenant_id: str, project_id: uuid.UUID, *, user: dict[str, Any]
) -> CortexNativeWorkspaceRead:
    project = await _get_project(db, tenant_id, project_id)
    _require_owner(user, project.owner_id)
    binding = get_binding(tenant_id, project.id)
    return CortexNativeWorkspaceRead(
        connected=bool(binding),
        name=binding.get("name") if binding else None,
        path_alias=binding.get("path_alias") if binding else None,
    )


async def sync_native_workspace(
    db: AsyncSession,
    tenant_id: str,
    project_id: uuid.UUID,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexNativeWorkspaceRead:
    project = await _get_project(db, tenant_id, project_id)
    _require_owner(user, project.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_native_folder_sync",
        target=str(project.id),
        target_type="cortex_project",
        context={"direction": "host_to_workspace"},
        ip_address=ip_address,
    )
    binding = get_binding(tenant_id, project.id)
    if not binding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No local folder is connected")
    synced = await _sync_bound_root(
        db, tenant_id, project, user=user, actor_id=actor_id, actor_name=actor_name, ip_address=ip_address
    )
    return CortexNativeWorkspaceRead(
        connected=True,
        name=binding.get("name"),
        path_alias=binding.get("path_alias"),
        file_count=synced["file_count"],
        synced_files=synced["synced_files"],
    )


async def list_projects(
    db: AsyncSession,
    tenant_id: str,
    *,
    user: dict[str, Any],
    owner_id: str,
) -> list[CortexProjectRead]:
    query = select(CortexProject).where(CortexProject.tenant_id == tenant_id, CortexProject.status == "active")
    if not _can_read_all(user):
        query = query.where(CortexProject.owner_id == owner_id)
    result = await db.execute(query.order_by(desc(CortexProject.updated_at)))
    return [CortexProjectRead.model_validate(item) for item in result.scalars().all()]


async def create_conversation(
    db: AsyncSession,
    payload: CortexConversationCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationRead:
    if payload.project_id:
        project = await _get_project(db, payload.tenant_id, payload.project_id)
        _require_owner(user, project.owner_id)
    await _authorize(
        db,
        tenant_id=payload.tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_create",
        target=str(payload.project_id or "standalone"),
        target_type="cortex_conversation",
        context={"mode": payload.mode, "classification": payload.classification, "source": payload.selected_source},
        ip_address=ip_address,
    )
    title_scan = scan_text(payload.title.strip(), redact=True)
    conversation = CortexConversation(
        tenant_id=payload.tenant_id,
        owner_id=actor_id,
        project_id=payload.project_id,
        title=(title_scan.redacted if title_scan.is_sensitive else payload.title.strip())[:255],
        mode=payload.mode,
        classification=payload.classification,
        selected_source=payload.selected_source,
    )
    db.add(conversation)
    await db.commit()
    await db.refresh(conversation)
    return CortexConversationRead.model_validate(conversation)


async def list_conversations(
    db: AsyncSession,
    tenant_id: str,
    *,
    user: dict[str, Any],
    owner_id: str,
    project_id: uuid.UUID | None = None,
    mode: str | None = None,
    include_archived: bool = False,
    limit: int = 100,
) -> list[CortexConversationRead]:
    query = select(CortexConversation).where(CortexConversation.tenant_id == tenant_id)
    if not _can_read_all(user):
        query = query.where(CortexConversation.owner_id == owner_id)
    if project_id:
        query = query.where(CortexConversation.project_id == project_id)
    if mode:
        query = query.where(CortexConversation.mode == mode)
    if not include_archived:
        query = query.where(CortexConversation.status == "active")
    result = await db.execute(query.order_by(desc(CortexConversation.updated_at)).limit(limit))
    return [CortexConversationRead.model_validate(item) for item in result.scalars().all()]


async def get_conversation_detail(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    *,
    user: dict[str, Any],
) -> CortexConversationDetail:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    result = await db.execute(
        select(CortexConversationMessage)
        .where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id == conversation.id,
        )
        .order_by(CortexConversationMessage.created_at, CortexConversationMessage.id)
    )
    return CortexConversationDetail(
        **CortexConversationRead.model_validate(conversation).model_dump(),
        messages=[_message_read(item) for item in result.scalars().all()],
    )


async def archive_conversation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_archive",
        target=str(conversation.id),
        target_type="cortex_conversation",
        context={"mode": conversation.mode, "project_id": str(conversation.project_id) if conversation.project_id else None},
        ip_address=ip_address,
    )
    conversation.status = "archived"
    conversation.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(conversation)
    return CortexConversationRead.model_validate(conversation)


async def move_conversation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexConversationMove,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    project = await _get_project(db, tenant_id, payload.project_id)
    _require_owner(user, project.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_move",
        target=str(project.id),
        target_type="cortex_project",
        context={"conversation_id": str(conversation.id), "source_mode": conversation.mode},
        ip_address=ip_address,
    )
    conversation.project_id = project.id
    conversation.mode = "cowork"
    conversation.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(conversation)
    return CortexConversationRead.model_validate(conversation)


async def rename_conversation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexConversationRename,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_rename",
        target=str(conversation.id),
        target_type="cortex_conversation",
        context={"mode": conversation.mode},
        ip_address=ip_address,
    )
    title_scan = scan_text(payload.title.strip(), redact=True)
    conversation.title = (title_scan.redacted if title_scan.is_sensitive else payload.title.strip())[:255]
    conversation.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(conversation)
    return CortexConversationRead.model_validate(conversation)


async def reopen_conversation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    if conversation.status == "deleted":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_reopen",
        target=str(conversation.id),
        target_type="cortex_conversation",
        context={"mode": conversation.mode, "project_id": str(conversation.project_id) if conversation.project_id else None},
        ip_address=ip_address,
    )
    conversation.status = "active"
    conversation.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(conversation)
    return CortexConversationRead.model_validate(conversation)


async def permanently_delete_conversation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationDeleteRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_delete",
        target=str(conversation.id),
        target_type="cortex_conversation",
        context={"mode": conversation.mode, "project_id": str(conversation.project_id) if conversation.project_id else None},
        ip_address=ip_address,
    )
    # Conversation-specific proposed change artifacts are only meaningful
    # alongside the conversation that proposed them; other artifacts remain
    # part of the project and are only disassociated, not removed.
    await db.execute(
        sa_delete(CortexArtifact).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.conversation_id == conversation.id,
            CortexArtifact.status == "proposed",
        )
    )
    await db.execute(
        update(CortexArtifact)
        .where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.conversation_id == conversation.id,
        )
        .values(conversation_id=None)
    )
    await db.execute(
        update(CortexConversation)
        .where(
            CortexConversation.tenant_id == tenant_id,
            CortexConversation.branch_of_id == conversation.id,
        )
        .values(branch_of_id=None, branch_message_id=None)
    )
    await db.execute(
        sa_delete(CortexConversationMessage).where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id == conversation.id,
        )
    )
    conversation_id_value = conversation.id
    await db.delete(conversation)
    await db.commit()
    return CortexConversationDeleteRead(id=conversation_id_value)


async def ingest_artifacts(
    db: AsyncSession,
    payload: CortexArtifactBatchCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
    mirror_to_native: bool = True,
) -> list[CortexArtifactRead]:
    project = await _get_project(db, payload.tenant_id, payload.project_id)
    _require_owner(user, project.owner_id)
    if payload.conversation_id:
        conversation = await _get_conversation(db, payload.tenant_id, payload.conversation_id)
        _require_owner(user, conversation.owner_id)
        if conversation.project_id != project.id:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Conversation is not in this project")

    scans = [scan_text(item.content, redact=False) for item in payload.files]
    audits = [audit_prompt(item.content[:12000]) for item in payload.files]
    await _authorize(
        db,
        tenant_id=payload.tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_artifact_ingest",
        target=str(project.id),
        target_type="cortex_project",
        context={
            "classification": payload.classification,
            "file_count": len(payload.files),
            "total_bytes": sum(len(item.content.encode("utf-8")) for item in payload.files),
            "contains_sensitive_data": any(scan.is_sensitive for scan in scans),
            "prompt_injection_risk": any(audit.is_injection_risk for audit in audits),
            "max_prompt_risk": max((audit.risk_score for audit in audits), default=0),
        },
        ip_address=ip_address,
    )

    if mirror_to_native:
        for item in payload.files:
            await mirror_write(payload.tenant_id, project.id, path=item.path, content=item.content)

    created: list[CortexArtifact] = []
    next_versions: dict[str, int] = {}
    for item in payload.files:
        if item.path not in next_versions:
            version_result = await db.execute(
                select(func.max(CortexArtifact.version)).where(
                    CortexArtifact.tenant_id == payload.tenant_id,
                    CortexArtifact.project_id == project.id,
                    CortexArtifact.path == item.path,
                )
            )
            next_versions[item.path] = int(version_result.scalar_one_or_none() or 0) + 1
        else:
            next_versions[item.path] += 1
        await db.execute(
            update(CortexArtifact)
            .where(
                CortexArtifact.tenant_id == payload.tenant_id,
                CortexArtifact.project_id == project.id,
                CortexArtifact.path == item.path,
                CortexArtifact.status == "active",
            )
            .values(status="superseded")
        )
        ciphertext, digest = encrypt_json({"content": item.content})
        artifact = CortexArtifact(
            tenant_id=payload.tenant_id,
            project_id=project.id,
            conversation_id=payload.conversation_id,
            path=item.path,
            mime_type=item.mime_type,
            size_bytes=len(item.content.encode("utf-8")),
            content_ciphertext=ciphertext,
            content_digest=digest,
            classification=payload.classification,
            version=next_versions[item.path],
            created_by=actor_id,
        )
        db.add(artifact)
        created.append(artifact)
    project.updated_at = datetime.utcnow()
    await db.commit()
    for artifact in created:
        await db.refresh(artifact)
    return [_artifact_read(item) for item in created]


async def list_artifacts(
    db: AsyncSession,
    tenant_id: str,
    project_id: uuid.UUID,
    *,
    user: dict[str, Any],
    include_versions: bool = False,
) -> list[CortexArtifactRead]:
    project = await _get_project(db, tenant_id, project_id)
    _require_owner(user, project.owner_id)
    query = select(CortexArtifact).where(
        CortexArtifact.tenant_id == tenant_id,
        CortexArtifact.project_id == project_id,
    )
    if not include_versions:
        query = query.where(CortexArtifact.status == "active")
    result = await db.execute(query.order_by(CortexArtifact.path, desc(CortexArtifact.version)))
    return [_artifact_read(item) for item in result.scalars().all()]


async def get_artifact(
    db: AsyncSession,
    tenant_id: str,
    artifact_id: uuid.UUID,
    *,
    user: dict[str, Any],
) -> CortexArtifactRead:
    result = await db.execute(
        select(CortexArtifact).where(CortexArtifact.tenant_id == tenant_id, CortexArtifact.id == artifact_id)
    )
    artifact = result.scalar_one_or_none()
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    project = await _get_project(db, tenant_id, artifact.project_id)
    _require_owner(user, project.owner_id)
    return _artifact_read(artifact, include_content=True)


async def delete_artifact(
    db: AsyncSession,
    tenant_id: str,
    artifact_id: uuid.UUID,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexArtifactRead:
    result = await db.execute(
        select(CortexArtifact).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.id == artifact_id,
            CortexArtifact.status == "active",
        )
    )
    artifact = result.scalar_one_or_none()
    if artifact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    project = await _get_project(db, tenant_id, artifact.project_id)
    _require_owner(user, project.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_artifact_archive",
        target=str(artifact.id),
        target_type="cortex_artifact",
        context={
            "project_id": str(project.id),
            "path_digest": hashlib.sha256(artifact.path.encode("utf-8")).hexdigest(),
            "version": artifact.version,
        },
        ip_address=ip_address,
    )
    await mirror_trash(tenant_id, project.id, path=artifact.path)
    artifact.status = "deleted"
    project.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(artifact)
    return _artifact_read(artifact)


async def update_artifact(
    db: AsyncSession,
    tenant_id: str,
    artifact_id: uuid.UUID,
    payload: CortexArtifactUpdate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexArtifactRead:
    result = await db.execute(
        select(CortexArtifact).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.id == artifact_id,
            CortexArtifact.status == "active",
        )
    )
    current = result.scalar_one_or_none()
    if current is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    project = await _get_project(db, tenant_id, current.project_id)
    _require_owner(user, project.owner_id)
    path_changed = payload.path != current.path
    content_scan = scan_text(payload.content, redact=False)
    prompt_audit = audit_prompt(payload.content[:12000])
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_artifact_update",
        target=str(current.id),
        target_type="cortex_artifact",
        context={
            "project_id": str(project.id),
            "path_changed": path_changed,
            "contains_sensitive_data": content_scan.is_sensitive,
            "prompt_injection_risk": prompt_audit.is_injection_risk,
            "size_bytes": len(payload.content.encode("utf-8")),
        },
        ip_address=ip_address,
    )
    if path_changed:
        # A move is mirrored as an in-place native rename (never a create-new +
        # trash-old), then the moved file's contents are refreshed.
        await mirror_rename(tenant_id, project.id, path=current.path, new_path=payload.path)
    await mirror_write(tenant_id, project.id, path=payload.path, content=payload.content)
    version_result = await db.execute(
        select(func.max(CortexArtifact.version)).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.project_id == project.id,
            CortexArtifact.path == payload.path,
        )
    )
    current.status = "moved" if path_changed else "superseded"
    ciphertext, digest = encrypt_json({"content": payload.content})
    updated_artifact = CortexArtifact(
        tenant_id=tenant_id,
        project_id=project.id,
        conversation_id=current.conversation_id,
        path=payload.path,
        mime_type=payload.mime_type,
        size_bytes=len(payload.content.encode("utf-8")),
        content_ciphertext=ciphertext,
        content_digest=digest,
        classification=current.classification,
        version=int(version_result.scalar_one_or_none() or 0) + 1,
        created_by=actor_id,
    )
    db.add(updated_artifact)
    project.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(updated_artifact)
    return _artifact_read(updated_artifact, include_content=True)


async def list_change_proposals(
    db: AsyncSession,
    tenant_id: str,
    project_id: uuid.UUID,
    *,
    user: dict[str, Any],
) -> list[CortexChangeProposalRead]:
    project = await _get_project(db, tenant_id, project_id)
    _require_owner(user, project.owner_id)
    result = await db.execute(
        select(CortexArtifact)
        .where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.project_id == project_id,
            CortexArtifact.status == "proposed",
            CortexArtifact.mime_type == _CHANGE_MIME,
        )
        .order_by(CortexArtifact.created_at)
    )
    proposals = list(result.scalars().all())
    current_by_path: dict[str, CortexArtifact | None] = {}
    for proposal in proposals:
        if proposal.path not in current_by_path:
            current_result = await db.execute(
                select(CortexArtifact)
                .where(
                    CortexArtifact.tenant_id == tenant_id,
                    CortexArtifact.project_id == project_id,
                    CortexArtifact.path == proposal.path,
                    CortexArtifact.status == "active",
                )
                .order_by(desc(CortexArtifact.version))
                .limit(1)
            )
            current_by_path[proposal.path] = current_result.scalar_one_or_none()
    return [_proposal_read(item, current_by_path.get(item.path)) for item in proposals]


async def review_change_proposal(
    db: AsyncSession,
    tenant_id: str,
    proposal_id: uuid.UUID,
    payload: CortexChangeReview,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexChangeProposalRead:
    result = await db.execute(
        select(CortexArtifact).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.id == proposal_id,
            CortexArtifact.status == "proposed",
            CortexArtifact.mime_type == _CHANGE_MIME,
        )
    )
    proposal = result.scalar_one_or_none()
    if proposal is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pending change proposal not found")
    project = await _get_project(db, tenant_id, proposal.project_id)
    _require_owner(user, project.owner_id)
    envelope = decrypt_json(proposal.content_ciphertext, proposal.content_digest)
    # For an approved move the base file lives at previous_path; the change is
    # applied to the new path via an in-place native rename below.
    base_path = envelope.get("previous_path") or envelope["path"]
    current_result = await db.execute(
        select(CortexArtifact)
        .where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.project_id == proposal.project_id,
            CortexArtifact.path == base_path,
            CortexArtifact.status == "active",
        )
        .order_by(desc(CortexArtifact.version))
        .limit(1)
    )
    current = current_result.scalar_one_or_none()
    read_before = _proposal_read(proposal, current)
    content = str(envelope.get("content") or "")
    content_scan = scan_text(content, redact=False)
    content_audit = audit_prompt(content[:12000])
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_agent_change_apply" if payload.decision == "approve" else "workspace_agent_change_reject",
        target=str(proposal.id),
        target_type="cortex_change_proposal",
        context={
            "project_id": str(project.id),
            "operation": envelope["operation"],
            "path_digest": hashlib.sha256(envelope["path"].encode("utf-8")).hexdigest(),
            "contains_sensitive_data": content_scan.is_sensitive,
            "prompt_injection_risk": content_audit.is_injection_risk,
            "reason_provided": bool(payload.reason.strip()),
        },
        ip_address=ip_address,
    )
    if payload.decision == "reject":
        proposal.status = "rejected"
        await db.commit()
        return read_before.model_copy(update={"status": "rejected"})

    operation = envelope["operation"]
    base_digest = envelope.get("base_digest")
    if operation == "create" and current is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The target file now exists; review a new proposal")
    if operation in {"update", "delete"}:
        if current is None or current.content_digest != base_digest:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The target file changed after this proposal was created")

    if operation == "delete":
        await mirror_trash(tenant_id, project.id, path=envelope["path"])
        current.status = "deleted"
        proposal.status = "applied_delete"
    else:
        previous_path = envelope.get("previous_path")
        moved = bool(previous_path and previous_path != envelope["path"])
        if moved:
            # Approved move: mirror the host file in place with a rename before
            # its refreshed contents are written to the new path.
            await mirror_rename(tenant_id, project.id, path=previous_path, new_path=envelope["path"])
        await mirror_write(tenant_id, project.id, path=envelope["path"], content=content)
        if current is not None:
            current.status = "moved" if moved else "superseded"
        ciphertext, digest = encrypt_json({"content": content})
        proposal.content_ciphertext = ciphertext
        proposal.content_digest = digest
        proposal.mime_type = str(envelope.get("mime_type") or "text/plain")[:128]
        proposal.size_bytes = len(content.encode("utf-8"))
        proposal.status = "active"
        proposal.created_by = actor_id
    project.updated_at = datetime.utcnow()
    await db.commit()
    return read_before.model_copy(update={"status": "applied"})


def _bounded_history(messages: list[CortexMessageRead], latest_content: str, budget: int = 118000) -> list[CortexMessage]:
    selected: list[CortexMessage] = []
    remaining = max(0, budget - len(latest_content))
    for item in reversed(messages):
        if len(item.content) > remaining:
            continue
        selected.append(CortexMessage(role=item.role, content=item.content))
        remaining -= len(item.content)
        if remaining <= 0:
            break
    selected.reverse()
    selected.append(CortexMessage(role="user", content=latest_content))
    return selected


async def _persist_change_proposals(
    db: AsyncSession,
    *,
    conversation: CortexConversation,
    changes: list[dict[str, Any]],
    source: str,
    actor_id: str,
) -> list[CortexArtifact]:
    if not conversation.project_id or not changes:
        return []
    created: list[CortexArtifact] = []
    for change in changes:
        current_result = await db.execute(
            select(CortexArtifact)
            .where(
                CortexArtifact.tenant_id == conversation.tenant_id,
                CortexArtifact.project_id == conversation.project_id,
                CortexArtifact.path == change["path"],
                CortexArtifact.status == "active",
            )
            .order_by(desc(CortexArtifact.version))
            .limit(1)
        )
        current = current_result.scalar_one_or_none()
        if change["operation"] == "create" and current is not None:
            continue
        if change["operation"] in {"update", "delete"} and current is None:
            continue
        version_result = await db.execute(
            select(func.max(CortexArtifact.version)).where(
                CortexArtifact.tenant_id == conversation.tenant_id,
                CortexArtifact.project_id == conversation.project_id,
                CortexArtifact.path == change["path"],
            )
        )
        envelope = {
            **change,
            "base_digest": current.content_digest if current else None,
        }
        ciphertext, digest = encrypt_json(envelope)
        proposal = CortexArtifact(
            tenant_id=conversation.tenant_id,
            project_id=conversation.project_id,
            conversation_id=conversation.id,
            path=change["path"],
            mime_type=_CHANGE_MIME,
            size_bytes=len(change.get("content", "").encode("utf-8")),
            content_ciphertext=ciphertext,
            content_digest=digest,
            classification=conversation.classification,
            version=int(version_result.scalar_one_or_none() or 0) + 1,
            status="proposed",
            created_by=f"agent:{source or actor_id}"[:255],
        )
        db.add(proposal)
        created.append(proposal)
    if created:
        await db.flush()
    return created


async def execute_turn(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexTurnCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
) -> CortexTurnRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    if conversation.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Reopen this conversation before sending new turns",
        )
    message_result = await db.execute(
        select(CortexConversationMessage)
        .where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id == conversation.id,
        )
        .order_by(desc(CortexConversationMessage.created_at), desc(CortexConversationMessage.id))
        .limit(20)
    )
    previous_rows = list(reversed(message_result.scalars().all()))
    previous = [_message_read(item) for item in previous_rows]
    parent_id = previous_rows[-1].id if previous_rows else None

    classification = payload.data_classification or conversation.classification
    source = payload.source or conversation.selected_source
    runtime_group = payload.runtime_group or "hybrid"

    project: CortexProject | None = None
    if conversation.project_id:
        project = await _get_project(db, tenant_id, conversation.project_id)

    requested_artifact_ids = list(dict.fromkeys(payload.artifact_ids))
    explicit_artifacts = bool(requested_artifact_ids)
    if (
        not requested_artifact_ids
        and payload.include_project_files
        and conversation.mode == "cowork"
        and conversation.project_id
    ):
        default_artifacts = await db.execute(
            select(CortexArtifact.id).where(
                CortexArtifact.tenant_id == tenant_id,
                CortexArtifact.project_id == conversation.project_id,
                CortexArtifact.status == "active",
            )
        )
        requested_artifact_ids = list(default_artifacts.scalars().all())

    context_manifest: ContextManifest | None = None
    latest_content = payload.content
    selected_artifacts: list[CortexArtifact] = []
    if requested_artifact_ids:
        artifact_result = await db.execute(
            select(CortexArtifact).where(
                CortexArtifact.tenant_id == tenant_id,
                CortexArtifact.id.in_(requested_artifact_ids),
                CortexArtifact.status == "active",
            )
        )
        artifacts_by_id = {item.id: item for item in artifact_result.scalars().all()}
        if explicit_artifacts:
            artifacts = [artifacts_by_id[item_id] for item_id in requested_artifact_ids if item_id in artifacts_by_id]
            if len(artifacts) != len(requested_artifact_ids):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="One or more workspace artifacts were not found")
        else:
            artifacts = list(artifacts_by_id.values())
        if conversation.project_id is None or any(item.project_id != conversation.project_id for item in artifacts):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-project artifact context denied")
        selected_artifacts = artifacts

    # Effective classification is the lattice-maximum across the request,
    # conversation, project, and every explicitly selected or automatically
    # included artifact. It is computed after selection so it reflects exactly
    # what this turn carries, and it is the single value that drives every
    # downstream decision: compiler egress, Gateway routing/payload, Trust
    # Fabric metadata, persisted message classification, and governance/audit.
    # An unrecognized classification fails closed (rejected before any Brain).
    classification_inputs = [classification, conversation.classification]
    if project is not None:
        classification_inputs.append(project.classification)
    classification_inputs.extend(item.classification for item in selected_artifacts)
    try:
        effective_classification = highest_classification(*classification_inputs)
    except UnknownClassification:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This workspace carries an unrecognized data classification and was blocked.",
        )

    if selected_artifacts:
        capsule = compile_context(
            artifacts=selected_artifacts,
            explicit=explicit_artifacts,
            explicit_order=requested_artifact_ids if explicit_artifacts else None,
            prompt=payload.content,
            source=source,
            runtime_group=runtime_group,
            effective_classification=effective_classification,
        )
        context_manifest = capsule.manifest
        if capsule.text:
            latest_content = f"{payload.content}\n\n{capsule.text}"
    ciphertext, digest = encrypt_json({"content": payload.content})
    user_message = CortexConversationMessage(
        tenant_id=tenant_id,
        conversation_id=conversation.id,
        role="user",
        content_ciphertext=ciphertext,
        content_digest=digest,
        classification=effective_classification,
        parent_message_id=parent_id,
    )
    db.add(user_message)
    await db.flush()

    try:
        gateway = await execute_cortex_gateway(
            db,
            CortexGatewayRequest(
            mode=conversation.mode,
            messages=_bounded_history(previous, latest_content),
            source=source,
            model=payload.model,
            data_classification=effective_classification,
            runtime_group=runtime_group,
            capability="executive",
            workspace_id=str(conversation.project_id or conversation.id),
            minimum_votes=payload.minimum_votes,
            tenant_id=tenant_id,
            context={
                **payload.context,
                "conversation_id": str(conversation.id),
                "project_id": str(conversation.project_id) if conversation.project_id else None,
                "artifact_count": len(requested_artifact_ids),
                "effective_classification": effective_classification,
                "agent_mode": bool(payload.agent_mode and conversation.mode == "cowork"),
                "context_manifest": context_manifest.to_dict() if context_manifest else None,
            },
            ),
        )
    except Exception:
        await db.rollback()
        raise
    if context_manifest is not None:
        context_manifest = finalize_context_provenance(
            context_manifest,
            gateway,
            effective_classification,
        )
    assistant_text = gateway.get("response")
    if not assistant_text:
        governance = gateway.get("governance") or {}
        assistant_text = f"{gateway.get('status', 'unavailable').replace('_', ' ').title()}: {governance.get('reason', 'No governed Brain returned a response.')}"
    proposal_rows: list[CortexArtifact] = []
    if payload.agent_mode and conversation.mode == "cowork" and conversation.project_id and gateway.get("response"):
        assistant_text, changes = _extract_change_requests(assistant_text)
        if changes:
            proposal_decision = await enforce(
                db,
                ActionRequest(
                    module="marcellus_workspace",
                    actor_id=f"{gateway.get('source') or 'cortex'}-agent",
                    actor_name="Enkstein Cowork agent",
                    actor_type="agent",
                    action="workspace_change_propose",
                    target=str(conversation.project_id),
                    target_type="cortex_project",
                    context={
                        "tenant_id": tenant_id,
                        "conversation_id": str(conversation.id),
                        "change_count": len(changes),
                        "operations": sorted({change["operation"] for change in changes}),
                        "data_classification": effective_classification,
                    },
                ),
            )
            if proposal_decision.allowed:
                proposal_rows = await _persist_change_proposals(
                    db,
                    conversation=conversation,
                    changes=changes,
                    source=str(gateway.get("source") or "cortex"),
                    actor_id=actor_id,
                )
            else:
                assistant_text += "\n\nFile change proposals were blocked by Trust Fabric."
    assistant_ciphertext, assistant_digest = encrypt_json({"content": assistant_text})
    persisted_governance = {
        **(gateway.get("governance") or {}),
        "routing": gateway.get("routing"),
        "confidence": gateway.get("confidence"),
        "agreement": gateway.get("agreement"),
        "votes": [
            {
                key: vote.get(key)
                for key in ("source", "provider", "model", "counted", "reason", "latency_ms", "policy_outcome")
            }
            for vote in gateway.get("votes", [])
        ],
        "change_proposal_ids": [str(item.id) for item in proposal_rows],
        "context_manifest": context_manifest.to_dict() if context_manifest else None,
        "effective_classification": effective_classification,
    }
    assistant = CortexConversationMessage(
        tenant_id=tenant_id,
        conversation_id=conversation.id,
        role="assistant",
        content_ciphertext=assistant_ciphertext,
        content_digest=assistant_digest,
        classification=effective_classification,
        source=gateway.get("source"),
        provider=gateway.get("provider"),
        model=gateway.get("model"),
        governance_json=json.dumps(persisted_governance, separators=(",", ":")),
        parent_message_id=user_message.id,
    )
    db.add(assistant)
    if conversation.title == "New conversation":
        title_scan = scan_text(payload.content.replace("\n", " ").strip()[:100], redact=True)
        conversation.title = (title_scan.redacted if title_scan.is_sensitive else payload.content.strip())[:80] or conversation.title
    conversation.selected_source = source
    conversation.classification = classification
    conversation.message_count += 2
    conversation.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user_message)
    await db.refresh(assistant)
    await db.refresh(conversation)
    return CortexTurnRead(
        conversation=CortexConversationRead.model_validate(conversation),
        user_message=_message_read(user_message),
        assistant_message=_message_read(assistant),
        gateway=gateway,
    )


async def branch_conversation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexBranchCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexConversationDetail:
    source = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, source.owner_id)
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_conversation_branch",
        target=str(source.id),
        target_type="cortex_conversation",
        context={"mode": source.mode, "project_id": str(source.project_id) if source.project_id else None},
        ip_address=ip_address,
    )
    marker_result = await db.execute(
        select(CortexConversationMessage).where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id == source.id,
            CortexConversationMessage.id == payload.message_id,
        )
    )
    marker = marker_result.scalar_one_or_none()
    if marker is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Branch message not found")
    rows_result = await db.execute(
        select(CortexConversationMessage)
        .where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id == source.id,
        )
        .order_by(CortexConversationMessage.created_at, CortexConversationMessage.id)
    )
    all_rows = rows_result.scalars().all()
    marker_index = next((index for index, row in enumerate(all_rows) if row.id == marker.id), None)
    if marker_index is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Branch message not found")
    rows = all_rows[: marker_index + 1]
    branch = CortexConversation(
        tenant_id=tenant_id,
        owner_id=actor_id,
        project_id=source.project_id,
        title=payload.title or f"{source.title} (branch)",
        mode=source.mode,
        classification=source.classification,
        selected_source=source.selected_source,
        branch_of_id=source.id,
        branch_message_id=marker.id,
        message_count=len(rows),
    )
    db.add(branch)
    await db.flush()
    parent_map: dict[uuid.UUID, uuid.UUID] = {}
    cloned: list[CortexConversationMessage] = []
    for row in rows:
        clone = CortexConversationMessage(
            tenant_id=tenant_id,
            conversation_id=branch.id,
            role=row.role,
            content_ciphertext=row.content_ciphertext,
            content_digest=row.content_digest,
            classification=row.classification,
            source=row.source,
            provider=row.provider,
            model=row.model,
            governance_json=row.governance_json,
            parent_message_id=parent_map.get(row.parent_message_id),
            created_at=row.created_at,
        )
        db.add(clone)
        await db.flush()
        parent_map[row.id] = clone.id
        cloned.append(clone)
    await db.commit()
    await db.refresh(branch)
    return CortexConversationDetail(
        **CortexConversationRead.model_validate(branch).model_dump(),
        messages=[_message_read(item) for item in cloned],
    )


async def create_security_investigation(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexSecurityInvestigationCreate,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexSecurityInvestigationRead:
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    participants = list(dict.fromkeys(item.strip().lower() for item in payload.participants if item.strip()))
    unsupported = sorted(set(participants) - _SECURITY_HANDOFF_PARTICIPANTS)
    if unsupported:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported Security handoff participant: {unsupported[0]}",
        )
    message_result = await db.execute(
        select(CortexConversationMessage)
        .where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id == conversation.id,
        )
        .order_by(desc(CortexConversationMessage.created_at), desc(CortexConversationMessage.id))
        .limit(8)
    )
    rows = list(reversed(message_result.scalars().all()))
    context_text = "\n".join(f"{row.role}: {_message_read(row).content}" for row in rows)
    context_scan = scan_text(context_text[:12000], redact=True)
    context_digest = hashlib.sha256(context_text.encode("utf-8")).hexdigest()
    await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_security_investigation",
        target=str(conversation.id),
        target_type="cortex_conversation",
        context={
            "classification": conversation.classification,
            "participant_count": len(participants),
            "contains_sensitive_data": context_scan.is_sensitive,
            "requires_approval": payload.requires_approval,
        },
        ip_address=ip_address,
    )
    job = await create_swarm_job(
        db,
        SwarmJobCreate(
            name=f"Cortex Investigation - {conversation.title}"[:255],
            profile="DEEP_INVESTIGATION",
            requested_by=actor_id,
            trigger_type="cortex_handoff",
            classification=conversation.classification,
            participants=participants,
            task_type="investigate_cortex_context",
            input={
                "tenant_id": tenant_id,
                "conversation_id": str(conversation.id),
                "project_id": str(conversation.project_id) if conversation.project_id else None,
                "classification": conversation.classification,
                "context_digest": context_digest,
                "context_redaction_required": context_scan.is_sensitive,
                "source": "marcellus_cortex",
                "requested_outcome": "evidence_risk_blast_radius_controls_and_actions",
            },
            parallelism=min(8, len(participants)),
            model_profile="swarm_judge_profile",
        ),
    )
    if payload.requires_approval:
        job.status = SwarmJobStatus.REQUIRES_APPROVAL
        job.final_summary = "Awaiting operator approval before Cortex investigation execution"
        await db.commit()
        await db.refresh(job)
    return CortexSecurityInvestigationRead(
        job_id=job.id,
        status=job.status.value,
        name=job.name,
        requires_approval=payload.requires_approval,
        conversation_id=conversation.id,
    )


async def search_workspace(
    db: AsyncSession,
    tenant_id: str,
    query_text: str,
    *,
    user: dict[str, Any],
    owner_id: str,
    limit: int = 50,
) -> list[CortexSearchResult]:
    query_text = query_text.strip().lower()
    conversation_query = select(CortexConversation).where(CortexConversation.tenant_id == tenant_id)
    if not _can_read_all(user):
        conversation_query = conversation_query.where(CortexConversation.owner_id == owner_id)
    conversation_result = await db.execute(conversation_query.order_by(desc(CortexConversation.updated_at)).limit(500))
    conversations = conversation_result.scalars().all()
    by_id = {item.id: item for item in conversations}
    results: list[CortexSearchResult] = []
    for conversation in conversations:
        if query_text in conversation.title.lower():
            results.append(CortexSearchResult(conversation=CortexConversationRead.model_validate(conversation)))
            if len(results) >= limit:
                return results
    if not by_id:
        return results
    message_result = await db.execute(
        select(CortexConversationMessage)
        .where(
            CortexConversationMessage.tenant_id == tenant_id,
            CortexConversationMessage.conversation_id.in_(list(by_id)),
        )
        .order_by(desc(CortexConversationMessage.created_at))
        .limit(2000)
    )
    matched_conversations = {item.conversation.id for item in results}
    for message in message_result.scalars().all():
        if message.conversation_id in matched_conversations:
            continue
        content = decrypt_json(message.content_ciphertext, message.content_digest)["content"]
        position = content.lower().find(query_text)
        if position < 0:
            continue
        start = max(0, position - 80)
        excerpt = content[start : position + len(query_text) + 120].replace("\n", " ")
        results.append(
            CortexSearchResult(
                conversation=CortexConversationRead.model_validate(by_id[message.conversation_id]),
                matching_message_id=message.id,
                excerpt=excerpt,
            )
        )
        matched_conversations.add(message.conversation_id)
        if len(results) >= limit:
            break
    return results


async def workspace_summary(
    db: AsyncSession,
    tenant_id: str,
    *,
    user: dict[str, Any],
    owner_id: str,
) -> CortexWorkspaceSummary:
    owner_filter = [] if _can_read_all(user) else [CortexProject.owner_id == owner_id]
    projects = await db.scalar(
        select(func.count()).select_from(CortexProject).where(CortexProject.tenant_id == tenant_id, *owner_filter)
    )
    conversation_filters = [] if _can_read_all(user) else [CortexConversation.owner_id == owner_id]
    conversations = await db.scalar(
        select(func.count()).select_from(CortexConversation).where(
            CortexConversation.tenant_id == tenant_id,
            CortexConversation.status == "active",
            *conversation_filters,
        )
    )
    accessible_projects_query = select(CortexProject.id).where(CortexProject.tenant_id == tenant_id, *owner_filter)
    accessible_projects = list((await db.execute(accessible_projects_query)).scalars().all())
    artifacts = 0
    if accessible_projects:
        artifacts = int(
            await db.scalar(
                select(func.count()).select_from(CortexArtifact).where(
                    CortexArtifact.tenant_id == tenant_id,
                    CortexArtifact.project_id.in_(accessible_projects),
                    CortexArtifact.status == "active",
                )
            )
            or 0
        )
    accessible_conversations_query = select(CortexConversation.id).where(
        CortexConversation.tenant_id == tenant_id,
        *conversation_filters,
    )
    accessible_conversations = list((await db.execute(accessible_conversations_query)).scalars().all())
    messages = 0
    if accessible_conversations:
        messages = int(
            await db.scalar(
                select(func.count()).select_from(CortexConversationMessage).where(
                    CortexConversationMessage.tenant_id == tenant_id,
                    CortexConversationMessage.conversation_id.in_(accessible_conversations),
                )
            )
            or 0
        )
    return CortexWorkspaceSummary(
        projects=int(projects or 0),
        active_conversations=int(conversations or 0),
        artifacts=artifacts,
        messages=messages,
    )
