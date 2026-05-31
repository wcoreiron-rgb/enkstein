"""
RegentClaw — CommandClaw / Remote Agent Control Plane

Remote agent lifecycle:
POST /remote-agents/register
POST /remote-agents/{id}/heartbeat
GET  /remote-agents
POST /remote-agents/{id}/dispatch
POST /remote-agents/{id}/revoke
POST /remote-agents/{id}/kill

Unified command ingress:
POST /commands
GET  /commands/recent
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models.agent import Agent, AgentStatus, ExecutionMode, RiskLevel
from app.models.event import Event, EventOutcome
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(tags=["CommandClaw / Remote Agents"])

_REMOTE_CLAW = "remoteagent"
_REMOTE_CATEGORY = "Remote Control Plane"
_DEFAULT_COMMAND_APPROVALS_REQUIRED = 2


def _load_json_object(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _agent_metadata(agent: Agent) -> dict:
    return _load_json_object(agent.scope_notes)


def _agent_out(agent: Agent) -> dict:
    metadata = _agent_metadata(agent)
    return {
        "id": str(agent.id),
        "agent_id": str(agent.id),
        "name": agent.name,
        "tenant_id": metadata.get("tenant_id"),
        "owner": metadata.get("owner") or agent.owner_name,
        "host": metadata.get("host"),
        "device": metadata.get("device"),
        "status": agent.status.value if hasattr(agent.status, "value") else str(agent.status),
        "last_seen": metadata.get("last_seen"),
        "allowed_claws": json.loads(agent.allowed_actions or "[]"),
        "allowed_connectors": json.loads(agent.allowed_connectors or "[]"),
        "allowed_actions": metadata.get("allowed_actions", []),
        "trust_score": metadata.get("trust_score", 50.0),
        "version": metadata.get("version"),
        "public_key": metadata.get("public_key"),
        "current_jobs": metadata.get("current_jobs", []),
        "kill_switch_status": metadata.get("kill_switch_status", "inactive"),
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


def _agent_status_value(agent: Agent) -> str:
    return agent.status.value if hasattr(agent.status, "value") else str(agent.status)


def _event_command_id(event: Event) -> str | None:
    payload = _load_json_object(event.metadata_json)
    context = payload.get("context") if isinstance(payload, dict) else {}
    if isinstance(context, dict):
        command_id = context.get("command_id")
        return str(command_id) if command_id else None
    return None


def _event_metadata(event: Event) -> dict:
    return _load_json_object(event.metadata_json)


def _event_context(event: Event) -> dict:
    metadata = _event_metadata(event)
    context = metadata.get("context") if isinstance(metadata, dict) else {}
    return context if isinstance(context, dict) else {}


def _required_command_approvals(event: Event, context: dict) -> int:
    requested = context.get("required_approvals")
    if isinstance(requested, int):
        return max(1, min(requested, 4))
    if context.get("mode") == "approval":
        return _DEFAULT_COMMAND_APPROVALS_REQUIRED
    if event.risk_score >= 70:
        return _DEFAULT_COMMAND_APPROVALS_REQUIRED
    return 1


def _approval_state(event: Event) -> dict:
    metadata = _event_metadata(event)
    context = _event_context(event)
    state = metadata.get("approval_state") if isinstance(metadata, dict) else None
    if not isinstance(state, dict):
        state = {}
    approvals = state.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
    required = state.get("required_approvals")
    if not isinstance(required, int):
        required = _required_command_approvals(event, context)
    status = state.get("status") or ("approved" if len(approvals) >= required else "pending")
    return {
        "required_approvals": max(1, required),
        "approvals": approvals,
        "status": status,
        "requester": context.get("requester") or event.actor_id or event.actor_name or "unknown",
    }


def _write_approval_state(event: Event, state: dict) -> None:
    metadata = _event_metadata(event)
    metadata["approval_state"] = state
    event.metadata_json = json.dumps(metadata)


class RemoteAgentRegisterRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    tenant_id: str = Field(..., min_length=2, max_length=128)
    owner: str = Field(..., min_length=2, max_length=255)
    host: str | None = Field(default=None, max_length=255)
    device: str | None = Field(default=None, max_length=255)
    allowed_claws: list[str] = Field(default_factory=list)
    allowed_connectors: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=lambda: ["run_swarm", "run_scan", "create_ticket"])
    trust_score: float = Field(default=50.0, ge=0, le=100)
    version: str | None = Field(default=None, max_length=64)
    public_key: str | None = Field(default=None, max_length=4096)


class RemoteHeartbeatRequest(BaseModel):
    status: str = Field(default="online", max_length=64)
    trust_score: float | None = Field(default=None, ge=0, le=100)
    current_jobs: list[str] = Field(default_factory=list)
    version: str | None = Field(default=None, max_length=64)


class CommandRequest(BaseModel):
    command_id: str = Field(..., min_length=3, max_length=128)
    source: str = Field(default="portal", max_length=64)
    requester: str = Field(..., min_length=3, max_length=255)
    tenant_id: str = Field(..., min_length=2, max_length=128)
    intent: str = Field(..., min_length=2, max_length=128)
    target: str = Field(..., min_length=2, max_length=255)
    scope: str = Field(default="default", max_length=255)
    mode: str = Field(default="approval", max_length=64)
    classification: str = Field(default="internal", max_length=64)
    remote_agent_id: str | None = Field(default=None)
    payload: dict = Field(default_factory=dict)


class CommandApprovalRequest(BaseModel):
    approver: str | None = Field(default=None, max_length=255)
    reason: str | None = Field(default=None, max_length=1024)


class CommandRejectionRequest(BaseModel):
    reviewer: str | None = Field(default=None, max_length=255)
    reason: str | None = Field(default=None, max_length=1024)


class CommandApprovalPolicyUpdateRequest(BaseModel):
    required_approvals: int = Field(..., ge=1, le=4)
    reason: str | None = Field(default=None, max_length=1024)


class BulkCommandReviewRequest(BaseModel):
    command_ids: list[str] = Field(..., min_length=1, max_length=100)
    decision: str = Field(..., pattern="^(approve|reject)$")
    reason: str | None = Field(default=None, max_length=1024)
    actor: str | None = Field(default=None, max_length=255)


async def _find_pending_command_event(db: AsyncSession, command_id: str) -> Event | None:
    result = await db.execute(
        select(Event)
        .where(Event.source_module == "commandclaw", Event.outcome == EventOutcome.REQUIRES_APPROVAL)
        .order_by(desc(Event.timestamp))
    )
    for candidate in result.scalars().all():
        if _event_command_id(candidate) == command_id:
            return candidate
    return None


async def _execute_command(db: AsyncSession, user: dict, body: CommandRequest) -> dict:
    decision = await enforce(
        db,
        ActionRequest(
            module="commandclaw",
            actor_id=user.get("sub", body.requester),
            actor_name=body.requester,
            actor_type="human",
            action=body.intent,
            target=body.target,
            target_type="command_target",
            context={
                "channel": "command",
                "tenant_id": body.tenant_id,
                "command_id": body.command_id,
                "requester": body.requester,
                "source": body.source,
                "scope": body.scope,
                "classification": body.classification,
                "mode": body.mode,
                "payload": body.payload,
            },
        ),
    )
    return {
        "command_id": body.command_id,
        "allowed": decision.allowed,
        "outcome": decision.outcome.value,
        "risk_score": decision.risk_score,
        "severity": decision.severity.value,
        "policy_name": decision.policy_name,
        "reason": decision.reason,
        "remote_agent_id": body.remote_agent_id,
        "intent": body.intent,
        "target": body.target,
    }


@router.post("/remote-agents/register")
async def register_remote_agent(
    body: RemoteAgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    metadata = {
        "tenant_id": body.tenant_id,
        "owner": body.owner,
        "host": body.host,
        "device": body.device,
        "allowed_actions": body.allowed_actions,
        "trust_score": body.trust_score,
        "version": body.version,
        "public_key": body.public_key,
        "current_jobs": [],
        "kill_switch_status": "inactive",
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    agent = Agent(
        name=body.name,
        description=f"Remote worker ({body.tenant_id})",
        claw=_REMOTE_CLAW,
        category=_REMOTE_CATEGORY,
        execution_mode=ExecutionMode.ASSIST,
        risk_level=RiskLevel.MEDIUM,
        allowed_actions=json.dumps(body.allowed_claws),
        allowed_connectors=json.dumps(body.allowed_connectors),
        scope_notes=json.dumps(metadata),
        owner_name=body.owner,
        status=AgentStatus.ACTIVE,
        is_builtin=False,
        is_external=False,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    return _agent_out(agent)


@router.post("/remote-agents/{agent_id}/heartbeat")
async def remote_agent_heartbeat(
    agent_id: UUID,
    body: RemoteHeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.claw == _REMOTE_CLAW))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Remote agent not found")

    metadata = _agent_metadata(agent)
    metadata["last_seen"] = datetime.now(timezone.utc).isoformat()
    metadata["heartbeat_status"] = body.status
    metadata["current_jobs"] = body.current_jobs
    if body.trust_score is not None:
        metadata["trust_score"] = body.trust_score
    if body.version:
        metadata["version"] = body.version
    agent.scope_notes = json.dumps(metadata)
    agent.last_run_at = datetime.now(timezone.utc)
    agent.last_run_status = body.status
    await db.commit()
    await db.refresh(agent)
    return _agent_out(agent)


@router.get("/remote-agents")
async def list_remote_agents(
    tenant_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Agent).where(Agent.claw == _REMOTE_CLAW, Agent.status != AgentStatus.RETIRED).order_by(desc(Agent.created_at))
    result = await db.execute(q)
    agents = result.scalars().all()
    if tenant_id:
        agents = [a for a in agents if _agent_metadata(a).get("tenant_id") == tenant_id]
    return {"count": len(agents), "agents": [_agent_out(a) for a in agents]}


@router.post("/commands")
async def execute_command(
    body: CommandRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if body.remote_agent_id:
        try:
            remote_agent_uuid = UUID(body.remote_agent_id)
        except Exception:
            raise HTTPException(status_code=422, detail="Invalid remote_agent_id")
        result = await db.execute(
            select(Agent).where(Agent.id == remote_agent_uuid, Agent.claw == _REMOTE_CLAW)
        )
        agent = result.scalar_one_or_none()
        if not agent:
            raise HTTPException(status_code=404, detail="Remote agent not found")
        if _agent_status_value(agent) not in {"active", "paused"}:
            raise HTTPException(status_code=409, detail="Remote agent is not dispatchable")
        metadata = _agent_metadata(agent)
        if metadata.get("kill_switch_status") == "active":
            raise HTTPException(status_code=409, detail="Remote agent kill switch is active")
        if metadata.get("tenant_id") and metadata.get("tenant_id") != body.tenant_id:
            raise HTTPException(status_code=403, detail="Tenant mismatch for remote agent dispatch")
        allowed_intents = metadata.get("allowed_actions") or []
        if allowed_intents and body.intent not in allowed_intents:
            raise HTTPException(
                status_code=403,
                detail=f"Intent '{body.intent}' is not allowed for this remote agent",
            )
    return await _execute_command(db, current_user, body)


@router.get("/commands/recent")
async def list_recent_commands(
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Event)
        .where(Event.source_module == "commandclaw")
        .order_by(desc(Event.timestamp))
        .limit(limit)
    )
    events = result.scalars().all()
    rows = []
    for e in events:
        rows.append(
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "actor": e.actor_name,
                "action": e.action,
                "target": e.target,
                "outcome": e.outcome.value if hasattr(e.outcome, "value") else str(e.outcome),
                "risk_score": e.risk_score,
                "policy_name": e.policy_name,
            }
        )
    return {"count": len(rows), "commands": rows}


@router.get("/commands/{command_id}/timeline")
async def command_timeline(
    command_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Event)
        .where(Event.source_module == "commandclaw")
        .order_by(desc(Event.timestamp))
        .limit(limit)
    )
    events = result.scalars().all()
    timeline = []
    for e in events:
        event_cmd_id = _event_command_id(e)
        if event_cmd_id != command_id and (e.target or "") != command_id:
            continue
        timeline.append(
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "actor": e.actor_name,
                "actor_id": e.actor_id,
                "action": e.action,
                "target": e.target,
                "outcome": e.outcome.value if hasattr(e.outcome, "value") else str(e.outcome),
                "severity": e.severity.value if hasattr(e.severity, "value") else str(e.severity),
                "risk_score": e.risk_score,
                "policy_name": e.policy_name,
                "reason": e.policy_reason,
                "description": e.description,
                "metadata": _event_metadata(e),
            }
        )
    if not timeline:
        raise HTTPException(status_code=404, detail="Command timeline not found")
    return {"command_id": command_id, "count": len(timeline), "timeline": timeline}


@router.get("/commands/pending")
async def list_pending_commands(
    limit: int = Query(default=50, ge=1, le=200),
    source: str | None = Query(default=None),
    requester: str | None = Query(default=None),
    min_risk: float | None = Query(default=None, ge=0, le=100),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Event)
        .where(Event.source_module == "commandclaw", Event.outcome == "requires_approval")
        .order_by(desc(Event.timestamp))
        .limit(limit)
    )
    events = result.scalars().all()
    rows = []
    for e in events:
        context = _event_context(e)
        if source and str(context.get("source", "")).lower() != source.lower():
            continue
        if requester and str(context.get("requester", "")).lower() != requester.lower():
            continue
        if min_risk is not None and float(e.risk_score or 0) < float(min_risk):
            continue
        approval_state = _approval_state(e)
        rows.append(
            {
                "command_id": _event_command_id(e),
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "actor": e.actor_name,
                "action": e.action,
                "target": e.target,
                "outcome": e.outcome.value if hasattr(e.outcome, "value") else str(e.outcome),
                "risk_score": e.risk_score,
                "policy_name": e.policy_name,
                "reason": e.policy_reason,
                "required_approvals": approval_state["required_approvals"],
                "approvals_received": len(approval_state["approvals"]),
                "approval_status": approval_state["status"],
            }
        )
    rows = [r for r in rows if r.get("command_id")]
    return {"count": len(rows), "commands": rows}


@router.get("/commands/{command_id}/status")
async def command_status(
    command_id: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Event)
        .where(Event.source_module == "commandclaw")
        .order_by(desc(Event.timestamp))
        .limit(300)
    )
    events = result.scalars().all()
    matched = []
    for e in events:
        event_cmd_id = _event_command_id(e)
        if event_cmd_id == command_id or (e.target or "") == command_id:
            matched.append(e)
    if not matched:
        raise HTTPException(status_code=404, detail="Command not found")

    # Events are desc by timestamp: first item is latest.
    latest = matched[0]
    root = next((e for e in reversed(matched) if _event_command_id(e) == command_id), matched[-1])
    approval_state = _approval_state(root) if latest.outcome in {EventOutcome.REQUIRES_APPROVAL, EventOutcome.ALLOWED, EventOutcome.BLOCKED} else {}
    return {
        "command_id": command_id,
        "latest_outcome": latest.outcome.value if hasattr(latest.outcome, "value") else str(latest.outcome),
        "latest_action": latest.action,
        "latest_policy_name": latest.policy_name,
        "latest_reason": latest.policy_reason,
        "latest_risk_score": latest.risk_score,
        "created_at": root.timestamp.isoformat() if root.timestamp else None,
        "updated_at": latest.timestamp.isoformat() if latest.timestamp else None,
        "requester": (_event_context(root).get("requester") if _event_context(root) else root.actor_name),
        "source": (_event_context(root).get("source") if _event_context(root) else None),
        "approval_state": approval_state,
    }


@router.post("/commands/{command_id}/approve")
async def approve_pending_command(
    command_id: str,
    body: CommandApprovalRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    event = await _find_pending_command_event(db, command_id)
    if not event:
        raise HTTPException(status_code=404, detail="Pending command not found")

    approval_state = _approval_state(event)
    requester = str(approval_state.get("requester") or "unknown")
    approver_id = str(current_user.get("sub", "unknown"))
    approver_display = body.approver or approver_id
    approval_principal = approver_display if body.approver else approver_id
    if approver_id == requester or approver_display == requester:
        raise HTTPException(status_code=403, detail="Self-approval is not allowed")
    if any(str(a.get("approved_by")) == str(approval_principal) for a in approval_state["approvals"]):
        raise HTTPException(status_code=409, detail="Approver already recorded for this command")

    approval_state["approvals"].append(
        {
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "approved_by": approval_principal,
            "approver_display": approver_display,
            "reason": body.reason or "approved",
        }
    )
    approvals_received = len(approval_state["approvals"])
    required = approval_state["required_approvals"]
    final_approved = approvals_received >= required
    approval_state["status"] = "approved" if final_approved else "pending"
    _write_approval_state(event, approval_state)
    event.requires_review = not final_approved
    if final_approved:
        event.outcome = EventOutcome.ALLOWED
        event.description = f"{event.description} [approved]"
    else:
        event.outcome = EventOutcome.REQUIRES_APPROVAL
        event.description = f"{event.description} [approval {approvals_received}/{required}]"

    db.add(
        Event(
            source_module="commandclaw",
            actor_id=approver_id,
            actor_name=approver_display,
            actor_type="human",
            action="approve_command" if final_approved else "approve_command_step",
            target=command_id,
            target_type="command",
            outcome=EventOutcome.ALLOWED if final_approved else EventOutcome.PENDING,
            severity=event.severity,
            risk_score=event.risk_score,
            policy_name="manual_command_approval",
            policy_reason=(
                body.reason
                or (
                    f"Approval step {approvals_received}/{required} recorded"
                    if not final_approved
                    else "Approved via CommandClaw approval endpoint"
                )
            ),
            description=(
                f"Approved pending command {command_id}"
                if final_approved
                else f"Recorded approval {approvals_received}/{required} for pending command {command_id}"
            ),
            metadata_json=json.dumps(
                {
                    "approved_command_id": command_id,
                    "approvals_received": approvals_received,
                    "approvals_required": required,
                    "final_approved": final_approved,
                }
            ),
            is_anomaly=False,
            requires_review=not final_approved,
        )
    )
    await db.commit()
    return {
        "command_id": command_id,
        "status": "approved" if final_approved else "pending_more_approvals",
        "approvals_received": approvals_received,
        "approvals_required": required,
    }


@router.post("/commands/{command_id}/reject")
async def reject_pending_command(
    command_id: str,
    body: CommandRejectionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    event = await _find_pending_command_event(db, command_id)
    if not event:
        raise HTTPException(status_code=404, detail="Pending command not found")

    reviewer_id = str(current_user.get("sub", "unknown"))
    reviewer_display = body.reviewer or reviewer_id

    approval_state = _approval_state(event)
    approval_state["status"] = "rejected"
    approval_state["rejected_at"] = datetime.now(timezone.utc).isoformat()
    approval_state["rejected_by"] = reviewer_display
    approval_state["reject_reason"] = body.reason or "rejected"
    _write_approval_state(event, approval_state)

    event.outcome = EventOutcome.BLOCKED
    event.requires_review = False
    event.policy_name = event.policy_name or "manual_command_rejection"
    event.policy_reason = body.reason or "Rejected via CommandClaw rejection endpoint"
    event.description = f"{event.description} [rejected]"

    db.add(
        Event(
            source_module="commandclaw",
            actor_id=reviewer_id,
            actor_name=reviewer_display,
            actor_type="human",
            action="reject_command",
            target=command_id,
            target_type="command",
            outcome=EventOutcome.BLOCKED,
            severity=event.severity,
            risk_score=event.risk_score,
            policy_name="manual_command_rejection",
            policy_reason=body.reason or "Rejected pending command",
            description=f"Rejected pending command {command_id}",
            metadata_json=json.dumps({"rejected_command_id": command_id}),
            is_anomaly=False,
            requires_review=False,
        )
    )
    await db.commit()
    return {"command_id": command_id, "status": "rejected"}


@router.post("/commands/{command_id}/approval-policy")
async def update_command_approval_policy(
    command_id: str,
    body: CommandApprovalPolicyUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    event = await _find_pending_command_event(db, command_id)
    if not event:
        raise HTTPException(status_code=404, detail="Pending command not found")

    approval_state = _approval_state(event)
    approvals_received = len(approval_state["approvals"])
    if body.required_approvals < approvals_received:
        raise HTTPException(
            status_code=400,
            detail="required_approvals cannot be lower than approvals already recorded",
        )
    old_required = approval_state["required_approvals"]
    approval_state["required_approvals"] = body.required_approvals
    approval_state["status"] = (
        "approved" if approvals_received >= body.required_approvals else "pending"
    )
    _write_approval_state(event, approval_state)
    event.description = f"{event.description} [approval-policy {old_required}->{body.required_approvals}]"

    db.add(
        Event(
            source_module="commandclaw",
            actor_id=str(current_user.get("sub", "unknown")),
            actor_name=str(current_user.get("sub", "unknown")),
            actor_type="human",
            action="update_command_approval_policy",
            target=command_id,
            target_type="command",
            outcome=EventOutcome.PENDING,
            severity=event.severity,
            risk_score=event.risk_score,
            policy_name="manual_command_policy_update",
            policy_reason=body.reason or f"Updated required approvals {old_required}->{body.required_approvals}",
            description=f"Updated approval requirement for command {command_id}",
            metadata_json=json.dumps(
                {
                    "command_id": command_id,
                    "old_required_approvals": old_required,
                    "new_required_approvals": body.required_approvals,
                }
            ),
            is_anomaly=False,
            requires_review=True,
        )
    )
    await db.commit()
    return {
        "command_id": command_id,
        "required_approvals": body.required_approvals,
        "approvals_received": approvals_received,
        "approval_status": approval_state["status"],
    }


@router.post("/commands/bulk-review")
async def bulk_review_pending_commands(
    body: BulkCommandReviewRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    unique_command_ids = list(dict.fromkeys(body.command_ids))
    if len(unique_command_ids) != len(body.command_ids):
        raise HTTPException(status_code=400, detail="command_ids must not contain duplicates")

    actor_id = str(current_user.get("sub", "unknown"))
    actor_display = body.actor or actor_id
    summary = {"requested": len(unique_command_ids), "processed": 0, "approved": 0, "rejected": 0, "errors": []}

    for command_id in unique_command_ids:
        event = await _find_pending_command_event(db, command_id)
        if not event:
            summary["errors"].append({"command_id": command_id, "detail": "Pending command not found"})
            continue

        if body.decision == "approve":
            approval_state = _approval_state(event)
            requester = str(approval_state.get("requester") or "unknown")
            if actor_id == requester or actor_display == requester:
                summary["errors"].append({"command_id": command_id, "detail": "Self-approval is not allowed"})
                continue
            if any(str(a.get("approved_by")) == str(actor_display) for a in approval_state["approvals"]):
                summary["errors"].append({"command_id": command_id, "detail": "Approver already recorded"})
                continue

            approval_state["approvals"].append(
                {
                    "approved_at": datetime.now(timezone.utc).isoformat(),
                    "approved_by": actor_display,
                    "approver_display": actor_display,
                    "reason": body.reason or "bulk approved",
                }
            )
            approvals_received = len(approval_state["approvals"])
            required = approval_state["required_approvals"]
            final_approved = approvals_received >= required
            approval_state["status"] = "approved" if final_approved else "pending"
            _write_approval_state(event, approval_state)
            event.requires_review = not final_approved
            event.outcome = EventOutcome.ALLOWED if final_approved else EventOutcome.REQUIRES_APPROVAL
            event.description = (
                f"{event.description} [bulk-approved]"
                if final_approved
                else f"{event.description} [bulk-approval {approvals_received}/{required}]"
            )
            db.add(
                Event(
                    source_module="commandclaw",
                    actor_id=actor_id,
                    actor_name=actor_display,
                    actor_type="human",
                    action="bulk_approve_command" if final_approved else "bulk_approve_command_step",
                    target=command_id,
                    target_type="command",
                    outcome=EventOutcome.ALLOWED if final_approved else EventOutcome.PENDING,
                    severity=event.severity,
                    risk_score=event.risk_score,
                    policy_name="manual_command_bulk_approval",
                    policy_reason=body.reason or "Bulk approval recorded",
                    description=(
                        f"Bulk approved pending command {command_id}"
                        if final_approved
                        else f"Bulk recorded approval {approvals_received}/{required} for {command_id}"
                    ),
                    metadata_json=json.dumps(
                        {
                            "approved_command_id": command_id,
                            "approvals_received": approvals_received,
                            "approvals_required": required,
                            "final_approved": final_approved,
                            "bulk_review": True,
                        }
                    ),
                    is_anomaly=False,
                    requires_review=not final_approved,
                )
            )
            summary["processed"] += 1
            if final_approved:
                summary["approved"] += 1
        else:
            approval_state = _approval_state(event)
            approval_state["status"] = "rejected"
            approval_state["rejected_at"] = datetime.now(timezone.utc).isoformat()
            approval_state["rejected_by"] = actor_display
            approval_state["reject_reason"] = body.reason or "bulk rejected"
            _write_approval_state(event, approval_state)

            event.outcome = EventOutcome.BLOCKED
            event.requires_review = False
            event.policy_name = event.policy_name or "manual_command_bulk_rejection"
            event.policy_reason = body.reason or "Rejected via bulk command review"
            event.description = f"{event.description} [bulk-rejected]"

            db.add(
                Event(
                    source_module="commandclaw",
                    actor_id=actor_id,
                    actor_name=actor_display,
                    actor_type="human",
                    action="bulk_reject_command",
                    target=command_id,
                    target_type="command",
                    outcome=EventOutcome.BLOCKED,
                    severity=event.severity,
                    risk_score=event.risk_score,
                    policy_name="manual_command_bulk_rejection",
                    policy_reason=body.reason or "Bulk rejected pending command",
                    description=f"Bulk rejected pending command {command_id}",
                    metadata_json=json.dumps({"rejected_command_id": command_id, "bulk_review": True}),
                    is_anomaly=False,
                    requires_review=False,
                )
            )
            summary["processed"] += 1
            summary["rejected"] += 1

    await db.commit()
    return summary


@router.post("/remote-agents/{agent_id}/dispatch")
async def dispatch_to_remote_agent(
    agent_id: UUID,
    body: CommandRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if body.remote_agent_id and body.remote_agent_id != str(agent_id):
        raise HTTPException(status_code=400, detail="remote_agent_id must match path agent_id")
    body.remote_agent_id = str(agent_id)
    return await execute_command(body=body, db=db, current_user=current_user)


@router.post("/remote-agents/{agent_id}/revoke")
async def revoke_remote_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.claw == _REMOTE_CLAW))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Remote agent not found")
    agent.status = AgentStatus.PAUSED
    metadata = _agent_metadata(agent)
    metadata["revoked_at"] = datetime.now(timezone.utc).isoformat()
    agent.scope_notes = json.dumps(metadata)
    await db.commit()
    await db.refresh(agent)
    return _agent_out(agent)


@router.post("/remote-agents/{agent_id}/kill")
async def kill_remote_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id, Agent.claw == _REMOTE_CLAW))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Remote agent not found")
    metadata = _agent_metadata(agent)
    metadata["kill_switch_status"] = "active"
    metadata["killed_at"] = datetime.now(timezone.utc).isoformat()
    agent.scope_notes = json.dumps(metadata)
    agent.status = AgentStatus.RETIRED
    await db.commit()
    await db.refresh(agent)
    return _agent_out(agent)
