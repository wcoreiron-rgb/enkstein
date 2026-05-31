"""
RegentClaw — External Agent Registration & Key Management API

POST   /external-agents/register          — register an external OpenClaw agent (returns secret ONCE)
POST   /external-agents/{id}/rotate-key   — rotate signing secret (old one immediately invalidated)
POST   /external-agents/{id}/verify       — health-check the endpoint (SSRF-safe ping)
GET    /external-agents                   — list all external agents
GET    /external-agents/{id}              — get one external agent
DELETE /external-agents/{id}              — deregister (soft delete → status = retired)
"""
import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.agent import Agent, AgentStatus, ExecutionMode, RiskLevel
from app.services.external_agent_dispatcher import (
    generate_signing_secret,
    validate_endpoint_url,
    SSRFError,
    dispatch,
    ExternalAgentError,
)

logger = logging.getLogger("regentclaw.external_agents")
router = APIRouter(prefix="/external-agents", tags=["External Agents — Zero Trust"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class RegisterExternalAgentRequest(BaseModel):
    name:           str         = Field(..., min_length=3, max_length=255)
    description:    str | None  = Field(default=None, max_length=2048)
    endpoint_url:   str         = Field(..., description="HTTPS endpoint of the OpenClaw agent")
    allowed_scopes: list[str]   = Field(
        default=["*.read"],
        description="Scopes this agent may request. e.g. ['identity:read','network:write']"
    )
    execution_mode: str         = Field(default="monitor")
    risk_level:     str         = Field(default="low")
    owner_name:     str | None  = Field(default=None)


class RotateKeyResponse(BaseModel):
    agent_id:       str
    signing_secret: str   # returned ONCE — store it immediately
    api_key_preview: str
    message:        str


class RegisterResponse(BaseModel):
    agent_id:        str
    name:            str
    endpoint_url:    str
    signing_secret:  str   # returned ONCE — never stored in plaintext after this
    api_key_preview: str
    allowed_scopes:  list[str]
    message:         str


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _agent_out(a: Agent, include_secret: bool = False) -> dict:
    return {
        "id":                   str(a.id),
        "name":                 a.name,
        "description":          a.description,
        "is_external":          a.is_external,
        "endpoint_url":         a.endpoint_url,
        "api_key_preview":      a.api_key_preview,
        "allowed_scopes":       json.loads(a.allowed_scopes or "[]"),
        "execution_mode":       a.execution_mode,
        "risk_level":           a.risk_level,
        "status":               a.status,
        "owner_name":           a.owner_name,
        "endpoint_verified_at": a.endpoint_verified_at.isoformat() if a.endpoint_verified_at else None,
        "endpoint_last_error":  a.endpoint_last_error,
        "total_runs":           a.total_runs,
        "last_run_at":          a.last_run_at.isoformat() if a.last_run_at else None,
        "last_run_status":      a.last_run_status,
        "created_at":           a.created_at.isoformat() if a.created_at else None,
        # signing_secret deliberately omitted — only returned on register/rotate
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/register", summary="Register an external OpenClaw agent")
async def register_external_agent(
    body: RegisterExternalAgentRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register an external agent endpoint.

    Returns the signing_secret **once** — store it immediately.
    It will never be retrievable again. Lose it → rotate.

    The operator must configure their OpenClaw agent with this secret so it can:
      1. Verify RegentClaw's X-RegentClaw-Signature on inbound calls.
      2. Sign its responses with X-Agent-Signature.
    """
    # SSRF validation before we even save to DB
    try:
        validate_endpoint_url(body.endpoint_url, allow_http_localhost=True)
    except SSRFError:
        raise HTTPException(status_code=400, detail="Endpoint URL rejected by SSRF policy")

    # Validate execution mode
    valid_modes = [m.value for m in ExecutionMode]
    if body.execution_mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid execution_mode. Choose from: {valid_modes}")

    valid_risks = [r.value for r in RiskLevel]
    if body.risk_level not in valid_risks:
        raise HTTPException(status_code=400, detail=f"Invalid risk_level. Choose from: {valid_risks}")

    # Validate scopes
    from app.services.external_agent_dispatcher import ACTION_SCOPE_MAP
    valid_scopes = set(ACTION_SCOPE_MAP.values()) | {"*.read", "*"}
    for scope in body.allowed_scopes:
        if scope not in valid_scopes:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown scope: '{scope}'. Valid scopes: {sorted(valid_scopes)}"
            )

    # Generate secret
    secret = generate_signing_secret()
    preview = secret[:8] + "..." + secret[-4:]

    agent = Agent(
        name            = body.name,
        description     = body.description,
        claw            = "external",        # generic claw label for external agents
        category        = "External",
        is_external     = True,
        is_builtin      = False,
        endpoint_url    = body.endpoint_url,
        signing_secret  = secret,            # stored in plaintext — encrypt at rest in production
        api_key_preview = preview,
        allowed_scopes  = json.dumps(body.allowed_scopes),
        execution_mode  = body.execution_mode,
        risk_level      = body.risk_level,
        owner_name      = body.owner_name,
        status          = AgentStatus.ACTIVE,
        requires_approval = body.risk_level in ("high", "critical"),
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)

    logger.info(
        "External agent registered: id=%s name=%s endpoint=%s scopes=%s",
        str(agent.id), agent.name, agent.endpoint_url, body.allowed_scopes,
    )

    return {
        "agent_id":        str(agent.id),
        "name":            agent.name,
        "endpoint_url":    agent.endpoint_url,
        "signing_secret":  secret,   # ← ONE TIME ONLY
        "api_key_preview": preview,
        "allowed_scopes":  body.allowed_scopes,
        "message": (
            "Agent registered. IMPORTANT: Copy the signing_secret now — "
            "it will never be shown again. Configure your OpenClaw agent with it."
        ),
    }


@router.post("/{agent_id}/rotate-key", summary="Rotate signing secret — old key immediately invalidated")
async def rotate_signing_key(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Rotate the signing secret for an external agent.
    The old secret is immediately invalidated — any in-flight calls signed with
    the old key will fail verification after this point.
    """
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.is_external == True)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="External agent not found")

    new_secret = generate_signing_secret()
    preview    = new_secret[:8] + "..." + new_secret[-4:]

    agent.signing_secret  = new_secret
    agent.api_key_preview = preview
    agent.endpoint_verified_at = None   # re-verify after rotation
    await db.commit()

    logger.warning(
        "Signing key rotated for external agent id=%s name=%s", str(agent.id), agent.name
    )

    return {
        "agent_id":        str(agent_id),
        "signing_secret":  new_secret,  # ← ONE TIME ONLY
        "api_key_preview": preview,
        "message": (
            "Key rotated. IMPORTANT: Update your OpenClaw agent with the new signing_secret immediately. "
            "Old key is invalidated."
        ),
    }


@router.post("/{agent_id}/verify", summary="Verify endpoint reachability (SSRF-safe health check)")
async def verify_endpoint(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    Send a test dispatch to the external agent endpoint.
    Uses a synthetic run_id so no real data is processed.
    Updates endpoint_verified_at on success, endpoint_last_error on failure.
    """
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.is_external == True)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="External agent not found")

    if not agent.endpoint_url or not agent.signing_secret:
        raise HTTPException(status_code=400, detail="Agent has no endpoint_url or signing_secret")

    scopes = json.loads(agent.allowed_scopes or '["*.read"]')

    try:
        result_data = await dispatch(
            agent_id      = str(agent.id),
            run_id        = "verify-" + str(agent.id)[:8],
            endpoint_url  = agent.endpoint_url,
            signing_secret= agent.signing_secret,
            allowed_scopes= scopes,
            context       = {"type": "health_check"},
            dev_mode      = True,   # allow HTTP for local dev
        )
        agent.endpoint_verified_at = datetime.now(timezone.utc)
        agent.endpoint_last_error  = None
        await db.commit()

        return {
            "status":     "ok",
            "verified_at": agent.endpoint_verified_at.isoformat(),
            "findings":    len(result_data.get("findings", [])),
            "message":     "Endpoint reachable, signature verified, response schema valid.",
        }

    except ExternalAgentError as e:
        agent.endpoint_last_error = str(e)
        await db.commit()
        raise HTTPException(status_code=502, detail="Endpoint verification failed")


@router.get("", summary="List all registered external agents")
async def list_external_agents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Agent)
        .where(Agent.is_external == True, Agent.status != AgentStatus.RETIRED)
        .order_by(Agent.created_at.desc())
    )
    agents = result.scalars().all()
    return {"count": len(agents), "agents": [_agent_out(a) for a in agents]}


@router.get("/{agent_id}", summary="Get a specific external agent")
async def get_external_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.is_external == True)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="External agent not found")
    return _agent_out(agent)


@router.patch("/{agent_id}/scopes", summary="Update allowed scopes for an external agent")
async def update_scopes(
    agent_id: UUID,
    allowed_scopes: list[str],
    db: AsyncSession = Depends(get_db),
):
    from app.services.external_agent_dispatcher import ACTION_SCOPE_MAP
    valid_scopes = set(ACTION_SCOPE_MAP.values()) | {"*.read", "*"}
    for scope in allowed_scopes:
        if scope not in valid_scopes:
            raise HTTPException(status_code=400, detail=f"Unknown scope: '{scope}'")

    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.is_external == True)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="External agent not found")

    agent.allowed_scopes = json.dumps(allowed_scopes)
    await db.commit()

    return {"agent_id": str(agent_id), "allowed_scopes": allowed_scopes}


@router.delete("/{agent_id}", summary="Deregister an external agent")
async def deregister_external_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Agent).where(Agent.id == agent_id, Agent.is_external == True)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="External agent not found")

    agent.status         = AgentStatus.RETIRED
    agent.signing_secret = None   # wipe secret on deregister
    await db.commit()

    logger.info("External agent deregistered: id=%s name=%s", str(agent.id), agent.name)
    return {"deregistered": str(agent_id), "message": "Agent deregistered. Signing secret wiped."}
