"""Trust Fabric-governed control plane over the native Codex App Server bridge.

Every operation is tenant/owner/project/conversation scoped. The web client
never supplies a raw cwd, thread id, workspace token, or scope digest: the
server resolves the encrypted native binding for the conversation's project and
derives a domain-separated scope digest from stable identifiers. Only that
derived digest plus the opaque binding token ever cross the bridge boundary, and
neither is ever returned to the client. Prompts, commands, approval details,
tokens, raw paths, and CLI event/response text are kept out of every
ActionRequest, audit record, and log line.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.claws.arcclaw.scanner import scan_text
from app.core.marcellus.context_compiler import (
    UnknownClassification,
    highest_classification,
    is_external_denied,
)
from app.core.marcellus.native_workspace import get_binding
from app.core.marcellus.token_hygiene import compact_tool_output
from app.core.marcellus.workspace import _get_conversation, _get_project, _require_owner
from app.core.marcellus.workspace_schemas import (
    CortexCodexApproval,
    CortexCodexApprovalRead,
    CortexCodexCancelRead,
    CortexCodexEvent,
    CortexCodexPendingApproval,
    CortexCodexStart,
    CortexCodexStartRead,
    CortexCodexStatusRead,
    CortexCodexTurn,
    CortexCodexTurnRead,
)
from app.core.modelclaw.brain_bridge import invoke_codex_bridge
from app.models.marcellus import CortexArtifact, CortexConversation, CortexProject
from app.trust_fabric import ActionRequest, EnforcementDecision, enforce
from app.trust_fabric.agt_bridge import audit_prompt


# The Codex App Server is an external subscription CLI, so any effective
# classification the canonical lattice marks external-denied (restricted /
# top_secret, and — failing closed — anything unrecognized) must be rejected
# before any native invocation. There is no explicit policy-override mechanism.

# Mirror of the Cortex gateway's prompt-injection blocking threshold so a turn is
# blocked consistently with a normal governed model call.
_INJECTION_BLOCK_SCORE = 50.0

# Bounds applied to native status output before it is returned to the owner.
_MAX_EVENTS = 50
_MAX_APPROVALS = 20
_MAX_FIELD_CHARS = 4000
_MAX_JSON_DEPTH = 6


def _scope_digest(
    tenant_id: str, owner_id: str, project_id: uuid.UUID, conversation_id: uuid.UUID
) -> str:
    """Derive the 64-char lowercase hex scope digest server-side.

    Domain-separated over stable tenant/owner/project/conversation identifiers so
    the client can never influence which native session a request binds to.
    """
    material = "\x00".join(
        [
            "marcellus.codex.scope.v1",
            tenant_id,
            owner_id,
            str(project_id),
            str(conversation_id),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


async def _preflight(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    *,
    user: dict[str, Any],
) -> tuple[CortexConversation, CortexProject, str, str, str]:
    """Resolve and authorize the scope for a Codex operation.

    Returns the conversation, its owning project, the opaque binding token, the
    derived scope digest, and the project's effective classification. The Codex
    App Server operates on the whole approved root, so the effective value is the
    lattice-maximum across the conversation, the project, and every active
    project artifact block (e.g. an internal conversation whose project contains
    a restricted file is effectively restricted). Unknown values fail closed.
    Never exposes the token or digest to callers of the HTTP surface.
    """
    conversation = await _get_conversation(db, tenant_id, conversation_id)
    _require_owner(user, conversation.owner_id)
    if conversation.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Reopen this conversation before using Codex",
        )
    if conversation.mode != "cowork":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Codex is only available in Cowork conversations",
        )
    if not conversation.project_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connect a Cowork project before using Codex",
        )
    project = await _get_project(db, tenant_id, conversation.project_id)
    _require_owner(user, project.owner_id)
    binding = get_binding(tenant_id, project.id)
    if not binding or not binding.get("token"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connect a local folder before using Codex",
        )
    digest = _scope_digest(tenant_id, conversation.owner_id, project.id, conversation.id)
    block_result = await db.execute(
        select(CortexArtifact.classification).where(
            CortexArtifact.tenant_id == tenant_id,
            CortexArtifact.project_id == project.id,
            CortexArtifact.status == "active",
        )
    )
    try:
        effective_classification = highest_classification(
            conversation.classification, project.classification, *block_result.scalars().all()
        )
    except UnknownClassification:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This project carries an unrecognized data classification and was blocked",
        )
    return conversation, project, binding["token"], digest, effective_classification


def _enforce_data_boundary(classification: str) -> None:
    if is_external_denied(classification):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Codex App Server is external and cannot process restricted data",
        )


async def _authorize(
    db: AsyncSession,
    *,
    tenant_id: str,
    actor_id: str,
    actor_name: str,
    action: str,
    conversation: CortexConversation,
    project: CortexProject,
    classification: str,
    metadata: dict[str, Any],
    ip_address: str | None = None,
) -> EnforcementDecision:
    """Run the Trust Fabric decision before a native Codex operation.

    Only safe metadata is included: tenant, conversation/project ids, the
    project's effective classification, and sandbox/decision/method identifiers.
    Never a prompt, command, approval detail, token, raw path, or response/event
    text.
    """
    return await enforce(
        db,
        ActionRequest(
            module="marcellus_workspace",
            actor_id=actor_id,
            actor_name=actor_name,
            actor_type="human",
            action=action,
            target=str(conversation.id),
            target_type="cortex_conversation",
            context={
                "tenant_id": tenant_id,
                "conversation_id": str(conversation.id),
                "project_id": str(project.id),
                "classification": classification,
                **metadata,
            },
        ),
        ip_address=ip_address,
    )


async def _invoke(operation: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Call the native Codex bridge, mapping failures to actionable HTTP errors
    without leaking broker internals."""
    try:
        return await invoke_codex_bridge(operation, payload)
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        code = exc.response.status_code if exc.response is not None else 502
        if code in {400, 404, 409}:
            # Actionable session-state conflict (e.g. no active session yet).
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The Codex session is not in a state that allows this action",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The Codex App Server bridge failed",
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The Codex App Server is not available",
        ) from exc
    except Exception as exc:  # noqa: BLE001 - normalized, non-leaking mapping
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The Codex App Server bridge is unreachable",
        ) from exc


# Structural keys inside native event payloads carry opaque correlation IDs,
# JSON-RPC method names, lifecycle labels, or numeric usage — never free-form
# CLI text — so they are preserved verbatim (bounded) to keep the client's
# cursor/lifecycle/approval handling working. Every other string is treated as
# untrusted streamed free text (agent-message delta, plan, unified diff, …) and
# is recursively scanned/redacted before it can be fanned out.
_STRUCTURAL_KEYS = frozenset(
    {
        "method", "channel", "type", "role", "status", "state", "phase", "step",
        "kind", "id", "itemId", "item_id", "turnId", "turn_id", "approval_id",
        "approvalId",
    }
)

# Keys that must never cross the boundary regardless of value: the native thread
# id, workspace token, and scope digest are server-only secrets.
_FORBIDDEN_KEYS = frozenset(
    {"threadId", "thread_id", "token", "scope_digest", "scopeDigest"}
)

# Approval-detail free-text fields that are redacted (command/reason/cwd) versus
# opaque identifiers that are preserved for client correlation.
_APPROVAL_FREE_TEXT = ("command", "reason", "cwd")
_APPROVAL_IDENTIFIERS = ("itemId", "turnId")
_ABSOLUTE_NATIVE_PATH = re.compile(
    r"(?:(?<![:/A-Za-z0-9_.-])/(?!/)[^\s'\"`]+|(?<![A-Za-z0-9_.-])[A-Za-z]:\\[^\r\n'\"`]+)"
)


def _remove_native_paths(text: str) -> str:
    return _ABSOLUTE_NATIVE_PATH.sub("[LOCAL_PATH]", text)


def _workspace_label(path: str) -> str:
    normalized = path.replace("\\", "/").rstrip("/")
    return (normalized.rsplit("/", 1)[-1] or "workspace")[:255]


@dataclass
class _NativeScanAccumulator:
    """Aggregates scan signal across a native status payload without retaining
    any raw streamed text: only counts and the free text needed for a single
    bounded injection audit are collected, and none of it is persisted."""

    free_text: list[str] = field(default_factory=list)
    fields_redacted: int = 0
    findings: int = 0

    def observe(self, text: str) -> str:
        safe_text = _remove_native_paths(text)
        # RTK-style compaction runs before this text is retained/redacted: it
        # only collapses noise (duplicate lines, progress redraws, info-level
        # log spam), so it cannot hide or reorder anything a later redaction
        # pass needs to see, and it shrinks what _MAX_FIELD_CHARS then cuts.
        safe_text = compact_tool_output(safe_text).text
        self.free_text.append(safe_text)
        scan = scan_text(safe_text, redact=True)
        if scan.is_sensitive:
            self.fields_redacted += 1
            self.findings += sum(int(finding.get("count") or 0) for finding in scan.findings)
            return scan.redacted[:_MAX_FIELD_CHARS]
        return safe_text[:_MAX_FIELD_CHARS]


def _redact_native_text(value: Any, acc: _NativeScanAccumulator, *, key: str | None = None, depth: int = 0) -> Any:
    """Bound and redact native event payloads: numbers/lifecycle preserved,
    structural IDs/method preserved, every other string recursively scanned and
    redacted so streamed CLI free text cannot leak secrets to the client."""
    if depth >= _MAX_JSON_DEPTH:
        return None
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        if key in _STRUCTURAL_KEYS:
            return value[:_MAX_FIELD_CHARS]
        return acc.observe(value)
    if isinstance(value, list):
        return [_redact_native_text(item, acc, key=key, depth=depth + 1) for item in value[:_MAX_EVENTS]]
    if isinstance(value, dict):
        bounded: dict[str, Any] = {}
        for raw_key in list(value)[:50]:
            key_str = str(raw_key)[:128]
            if key_str in _FORBIDDEN_KEYS:
                continue
            bounded[key_str] = _redact_native_text(value[raw_key], acc, key=key_str, depth=depth + 1)
        return bounded
    return acc.observe(str(value))


def _scan_metadata(acc: _NativeScanAccumulator) -> dict[str, Any]:
    """Safe aggregate scan metadata only — never any streamed raw text."""
    audit = audit_prompt("\n".join(acc.free_text)[:12000]) if acc.free_text else None
    return {
        "fields_redacted": acc.fields_redacted,
        "sensitive_findings": acc.findings,
        "output_redacted": acc.fields_redacted > 0,
        "injection_risk": bool(audit.is_injection_risk) if audit else False,
    }


def _sanitize_events(raw_events: Any, acc: _NativeScanAccumulator) -> list[CortexCodexEvent]:
    if not isinstance(raw_events, list):
        return []
    events: list[CortexCodexEvent] = []
    for raw in raw_events[:_MAX_EVENTS]:
        if not isinstance(raw, dict):
            continue
        fields = raw.get("fields")
        events.append(
            CortexCodexEvent(
                cursor=int(raw.get("cursor") or 0),
                channel=str(raw.get("channel") or "notification")[:64],
                fields=_redact_native_text(fields, acc) if isinstance(fields, dict) else {},
            )
        )
    return events


def _sanitize_approvals(raw_approvals: Any, acc: _NativeScanAccumulator) -> list[CortexCodexPendingApproval]:
    if not isinstance(raw_approvals, list):
        return []
    approvals: list[CortexCodexPendingApproval] = []
    for raw in raw_approvals[:_MAX_APPROVALS]:
        if not isinstance(raw, dict):
            continue
        approval_id = str(raw.get("approval_id") or "")[:64]
        if not approval_id:
            continue
        method = str(raw.get("method") or "")[:128]
        deny_only = method == "item/permissions/requestApproval"
        detail: dict[str, Any] = {}
        if not deny_only and isinstance(raw.get("detail"), dict):
            # Duplicate the native boundary's narrow allowlist so a compromised
            # or newer broker cannot smuggle arbitrary fields into the browser.
            # Command/reason/cwd are untrusted free text and are scanned/redacted;
            # item/turn identifiers are opaque correlation IDs preserved verbatim.
            for key in _APPROVAL_FREE_TEXT:
                value = raw["detail"].get(key)
                if isinstance(value, str) and value:
                    detail[key] = acc.observe(_workspace_label(value) if key == "cwd" else value)
            for key in _APPROVAL_IDENTIFIERS:
                value = raw["detail"].get(key)
                if isinstance(value, str) and value:
                    detail[key] = value[:_MAX_FIELD_CHARS]
        approvals.append(
            CortexCodexPendingApproval(
                approval_id=approval_id,
                method=method,
                detail=detail,
                deny_only=deny_only,
            )
        )
    return approvals


async def codex_start(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexCodexStart,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexCodexStartRead:
    conversation, project, token, digest, effective_classification = await _preflight(
        db, tenant_id, conversation_id, user=user
    )
    _enforce_data_boundary(effective_classification)
    decision = await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_codex_start",
        conversation=conversation,
        project=project,
        classification=effective_classification,
        metadata={"sandbox": payload.sandbox, "runtime_group": payload.runtime_group or "hybrid"},
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Codex start denied by {decision.policy_name}",
        )
    result = await _invoke("start", {"scope_digest": digest, "token": token, "sandbox": payload.sandbox})
    return CortexCodexStartRead(
        status=str(result.get("status") or "running")[:32],
        sandbox=str(result.get("sandbox") or payload.sandbox)[:32],
        resumed=bool(result.get("resumed")),
    )


async def codex_turn(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    payload: CortexCodexTurn,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexCodexTurnRead:
    conversation, project, token, digest, effective_classification = await _preflight(
        db, tenant_id, conversation_id, user=user
    )
    _enforce_data_boundary(effective_classification)

    scan = scan_text(payload.prompt, redact=True)
    audit = audit_prompt(payload.prompt[:12000])
    if audit.is_injection_risk and audit.risk_score >= _INJECTION_BLOCK_SCORE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The turn was blocked by Enkstein Prompt Defense",
        )
    decision = await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_codex_turn",
        conversation=conversation,
        project=project,
        classification=effective_classification,
        metadata={
            "runtime_group": payload.runtime_group or "hybrid",
            "contains_sensitive_data": scan.is_sensitive,
            "prompt_injection_risk": audit.is_injection_risk,
        },
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Codex turn denied by {decision.policy_name}",
        )
    # Detected secrets are redacted before the prompt reaches the external CLI.
    transmitted_prompt = scan.redacted if scan.is_sensitive else payload.prompt
    result = await _invoke(
        "turn", {"scope_digest": digest, "token": token, "prompt": transmitted_prompt}
    )
    return CortexCodexTurnRead(
        status=str(result.get("status") or "running")[:32],
        cursor=int(result.get("cursor") or 0),
        turn_active=bool(result.get("turnId") or result.get("turn_id")),
        policy={
            "input_redacted": scan.is_sensitive,
            "injection_risk": audit.is_injection_risk,
        },
    )


async def codex_status(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    cursor: int,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexCodexStatusRead:
    conversation, project, token, digest, effective_classification = await _preflight(
        db, tenant_id, conversation_id, user=user
    )
    _enforce_data_boundary(effective_classification)
    decision = await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_codex_status",
        conversation=conversation,
        project=project,
        classification=effective_classification,
        metadata={"cursor": max(0, cursor)},
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Codex status denied by {decision.policy_name}",
        )
    result = await _invoke("status", {"scope_digest": digest, "token": token, "cursor": max(0, cursor)})
    # Recursively scan/redact every free-text field in the native status before
    # it is returned; preserve cursor/method/IDs/lifecycle/numeric usage and
    # persist no streamed raw text — only safe aggregate scan metadata is emitted.
    scan_acc = _NativeScanAccumulator()
    events = _sanitize_events(result.get("events"), scan_acc)
    pending_approvals = _sanitize_approvals(result.get("pending_approvals"), scan_acc)
    return CortexCodexStatusRead(
        status=str(result.get("status") or "interrupted")[:32],
        transport=str(result.get("transport") or "interrupted")[:32],
        session=str(result.get("session") or "interrupted")[:32],
        turn=str(result.get("turn") or "idle")[:32],
        cursor=int(result.get("cursor") or 0),
        events=events,
        pending_approvals=pending_approvals,
        scan=_scan_metadata(scan_acc),
    )


async def codex_approval(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    approval_id: str,
    payload: CortexCodexApproval,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexCodexApprovalRead:
    conversation, project, token, digest, effective_classification = await _preflight(
        db, tenant_id, conversation_id, user=user
    )
    _enforce_data_boundary(effective_classification)
    decision = await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_codex_approve",
        conversation=conversation,
        project=project,
        classification=effective_classification,
        metadata={"decision": payload.decision},
        ip_address=ip_address,
    )
    if not decision.allowed:
        # A denied operator accept must not leave the turn hanging on the pending
        # approval: send a governed native decline first, then fail closed.
        if payload.decision == "accept":
            try:
                containment = await _authorize(
                    db,
                    tenant_id=tenant_id,
                    actor_id=actor_id,
                    actor_name=actor_name,
                    action="workspace_codex_decline_on_denial",
                    conversation=conversation,
                    project=project,
                    classification=effective_classification,
                    metadata={"decision": "decline", "containment": True},
                    ip_address=ip_address,
                )
                if containment.allowed:
                    await _invoke(
                        "approve",
                        {
                            "scope_digest": digest,
                            "token": token,
                            "approval_id": approval_id,
                            "decision": "decline",
                        },
                    )
            except HTTPException:
                pass
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Codex approval denied by {decision.policy_name}",
        )
    result = await _invoke(
        "approve",
        {
            "scope_digest": digest,
            "token": token,
            "approval_id": approval_id,
            "decision": payload.decision,
        },
    )
    return CortexCodexApprovalRead(
        status=str(result.get("status") or "ok")[:32],
        decision=str(result.get("decision") or payload.decision)[:32],
        governed=True,
    )


async def codex_cancel(
    db: AsyncSession,
    tenant_id: str,
    conversation_id: uuid.UUID,
    *,
    user: dict[str, Any],
    actor_id: str,
    actor_name: str,
    ip_address: str | None = None,
) -> CortexCodexCancelRead:
    conversation, project, token, digest, effective_classification = await _preflight(
        db, tenant_id, conversation_id, user=user
    )
    _enforce_data_boundary(effective_classification)
    decision = await _authorize(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_name=actor_name,
        action="workspace_codex_cancel",
        conversation=conversation,
        project=project,
        classification=effective_classification,
        metadata={},
        ip_address=ip_address,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Codex cancel denied by {decision.policy_name}",
        )
    result = await _invoke("cancel", {"scope_digest": digest, "token": token})
    return CortexCodexCancelRead(status=str(result.get("status") or "idle")[:32])
