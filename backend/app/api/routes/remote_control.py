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
from app.models.event import Event
from app.trust_fabric import ActionRequest, enforce

router = APIRouter(tags=["CommandClaw / Remote Agents"])

_REMOTE_CLAW = "remoteagent"
_REMOTE_CATEGORY = "Remote Control Plane"


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
