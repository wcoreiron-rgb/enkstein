"""Trust Fabric routes — runtime enforcement and AGT checks."""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import caller_tenant
from app.fabric.providers.agt import get_agt_adapter
from app.models.connector import Connector, ConnectorRisk, ConnectorStatus
from app.models.event import Event
from app.models.identity import Identity, IdentityStatus, IdentityType
from app.models.module import Module, ModuleStatus
from app.models.policy import Policy, PolicyAction, PolicyScope
from app.services.sre_policy import get_sre_engine
from app.trust_fabric import ActionRequest, block_connector, enforce, isolate_module, suspend_identity
from app.trust_fabric.agt_bridge import audit_prompt, scan_requirements

router = APIRouter(prefix="/trust-fabric", tags=["Trust Fabric"])


class TrustActionPayload(BaseModel):
    module: str = Field(default="trust_fabric", max_length=64)
    actor_id: str = Field(default="portal-user", max_length=256)
    actor_name: str = Field(default="Portal User", max_length=255)
    actor_type: str = Field(default="human", max_length=64)
    action: str = Field(default="read_status", max_length=128)
    target: Optional[str] = Field(default="trust-fabric", max_length=512)
    target_type: Optional[str] = Field(default="module", max_length=64)
    context: dict[str, Any] = Field(default_factory=dict)


class GuardActionPayload(BaseModel):
    """Privacy-safe evidence from Enkstein Guard.

    Raw prompts, file contents, command arguments, paths, secrets, and working
    directories are deliberately absent. The hook sends only deterministic
    classifications and one-way digests, which are sufficient for policy and
    audit without turning the audit database into a second disclosure.
    """

    model_config = ConfigDict(extra="forbid")

    surface: Literal["prompt", "write", "command"]
    tool: str = Field(..., min_length=1, max_length=64)
    operation: str = Field(..., min_length=1, max_length=128)
    target_kind: str = Field(default="unknown", max_length=64)
    target_labels: list[str] = Field(default_factory=list, max_length=20)
    target_digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    content_digest: str = Field(..., pattern=r"^[a-f0-9]{64}$")
    content_length: int = Field(default=0, ge=0, le=10_000_000)
    local_decision: Literal["allow", "monitor", "mask", "require_approval", "deny"]
    local_policy_ids: list[str] = Field(default_factory=list, max_length=128)
    local_findings_count: int = Field(default=0, ge=0, le=10_000)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_level: Literal["none", "low", "medium", "high", "critical"] = "none"
    is_sensitive: bool = False
    prompt_injection_risk: bool = False
    signals: dict[str, bool | int | float] = Field(default_factory=dict)


class PromptAuditPayload(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=12000)


class MCPScanPayload(BaseModel):
    target_type: str = Field(default="skill", pattern="^(skill|mcp|connector)$")
    path: str = Field(..., min_length=1, max_length=1024)

class MessageVerifyPayload(BaseModel):
    envelope: str = Field(..., min_length=8, max_length=200000)
    signature: str = Field(..., min_length=8, max_length=4096)
    key_id: str | None = Field(default=None, max_length=128)


class SREResetPayload(BaseModel):
    module: str | None = Field(default=None, max_length=64)


def _requirements_path() -> str:
    """Find requirements.txt in local dev and container layouts."""
    backend_root = Path(__file__).resolve().parents[3]
    candidates = [
        backend_root / "requirements.txt",
        Path("/app/requirements.txt"),
        Path.cwd() / "requirements.txt",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def _decision_payload(decision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "outcome": decision.outcome.value,
        "policy_action": getattr(getattr(decision, "policy_action", None), "value", None),
        "risk_score": decision.risk_score,
        "severity": decision.severity.value,
        "policy_name": decision.policy_name,
        "reason": decision.reason,
        "anomalies": decision.anomalies,
        "policy_coverage": getattr(decision, "policy_coverage", {}),
    }


@router.get("/status", summary="Trust Fabric runtime and AGT status")
async def get_trust_fabric_status(db: AsyncSession = Depends(get_db)):
    adapter = get_agt_adapter()
    agt = adapter.status()
    bridge = agt.get("bridge", {})
    # Backward compatibility for existing UI/tests that read AGT fields
    agt_view = {
        **bridge,
        **{k: v for k, v in agt.items() if k != "bridge"},
    }
    supply_chain = scan_requirements(_requirements_path())

    recent_result = await db.execute(select(Event).order_by(desc(Event.timestamp)).limit(5))
    recent_decisions = [
        {
            "id": str(event.id),
            "timestamp": event.timestamp.isoformat(),
            "module": event.source_module,
            "actor": event.actor_name,
            "action": event.action,
            "target": event.target,
            "outcome": event.outcome.value,
            "severity": event.severity.value,
            "risk_score": event.risk_score,
            "policy_name": event.policy_name,
            "is_anomaly": event.is_anomaly,
        }
        for event in recent_result.scalars().all()
    ]

    return {
        "runtime": {
            "available": True,
            "engine": "Enkstein deterministic policy engine",
            "checks": [
                "identity",
                "policy",
                "anomaly",
                "risk_scoring",
                "audit_log",
            ],
        },
        "agt": agt_view,
        "supply_chain": {
            "is_safe": supply_chain.is_safe,
            "risk_score": supply_chain.risk_score,
            "issues": supply_chain.issues,
            "typosquatting_hits": supply_chain.typosquatting_hits,
            "outdated_packages": supply_chain.outdated_packages,
            "agt_used": supply_chain.agt_used,
            "requirements_path": _requirements_path(),
        },
        "recent_decisions": recent_decisions,
    }


@router.get("/multi-agent/status", summary="Multi-agent capability status")
async def get_multi_agent_status():
    adapter = get_agt_adapter()
    status = adapter.status()
    features = status["features"]
    return {
        "provider": "agt",
        "enabled": bool(features["enable_agent_mesh"] or features["enable_e2e_messaging"]),
        "agent_mesh_enabled": features["enable_agent_mesh"],
        "encrypted_messaging_enabled": features["enable_e2e_messaging"],
        "cryptographic_identity_enabled": bool(status.get("crypto_identity", {}).get("enabled")),
        "signature_algorithm": status.get("crypto_identity", {}).get("algorithm"),
        "key_id": status.get("crypto_identity", {}).get("key_id"),
        "compatibility_mode": features["version_mode"],
        "rollout_note": "Feature-flagged rollout via Regent Fabric adapter boundary.",
    }


@router.post("/mcp/scan", summary="Scan MCP/skill/connector path through AGT scanner")
async def scan_mcp_skill_path(payload: MCPScanPayload):
    adapter = get_agt_adapter()
    result = adapter.scan_path(payload.path)
    result["target_type"] = payload.target_type
    result["mcp_gateway_enabled"] = adapter.flags.enable_mcp_gateway
    return result


@router.post("/multi-agent/verify", summary="Verify signed inter-agent message envelope")
async def verify_multi_agent_message(payload: MessageVerifyPayload):
    adapter = get_agt_adapter()
    return adapter.verify_secure_message(
        envelope=payload.envelope,
        signature=payload.signature,
        key_id=payload.key_id,
    )


@router.get("/sre/status", summary="SRE policy status and error budget state")
async def get_sre_status():
    return get_sre_engine().get_overview()


@router.post("/sre/reset", summary="Reset SRE policy state")
async def reset_sre_state(payload: SREResetPayload):
    return get_sre_engine().reset(module=payload.module)


@router.post("/evaluate", summary="Evaluate an action through Trust Fabric")
async def evaluate_trust_action(
    payload: TrustActionPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    sre = get_sre_engine()
    if settings.SRE_POLICY_ENABLED:
        allowed, reason = sre.check_circuit(payload.module)
        if not allowed:
            return {
                "allowed": False,
                "outcome": "blocked",
                "risk_score": 95.0,
                "severity": "critical",
                "policy_name": "sre_circuit_breaker",
                "reason": reason,
                "anomalies": ["sre_circuit_open"],
            }

    action_request = ActionRequest(**payload.model_dump())
    decision = await enforce(db, action_request, ip_address=request.client.host if request.client else None)
    if settings.SRE_POLICY_ENABLED:
        sre.record_outcome(payload.module, success=decision.allowed)
    return _decision_payload(decision)


_GUARD_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}$")
_GUARD_RESERVED_SIGNALS = {
    "module", "actor_id", "actor_name", "actor_type", "action", "target",
    "target_type", "tenant_id", "channel", "surface", "tool",
    "target_digest", "content_digest", "content_length", "local_decision",
    "local_policy_ids", "local_findings_count", "risk_score", "risk_level",
    "is_sensitive", "agt_injection_risk", "auth_token",
}


@router.post("/guard/evaluate", summary="Evaluate Enkstein Guard evidence across CoreOS")
async def evaluate_guard_action(
    payload: GuardActionPayload,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Apply the complete active CoreOS catalog to a coding-agent action.

    The Guard hook performs content inspection on the developer's machine and
    sends only safe evidence. This endpoint must never accept or persist raw
    prompt text, source content, command arguments, filesystem paths, or a
    working directory.
    """
    tenant_id = caller_tenant(user)
    policy_ids = [
        value for value in payload.local_policy_ids
        if _GUARD_IDENTIFIER.fullmatch(value)
    ]
    labels = [
        value.lower() for value in payload.target_labels
        if _GUARD_IDENTIFIER.fullmatch(value)
    ]
    safe_signals = {
        key: value
        for key, value in payload.signals.items()
        if (_GUARD_IDENTIFIER.fullmatch(key)
            and key not in _GUARD_RESERVED_SIGNALS)
    }

    action_request = ActionRequest(
        module="enkstein_guard",
        actor_id=f"coding-agent:{str(user.get('sub') or 'unknown')[:128]}",
        actor_name=f"Enkstein Guard ({payload.tool})",
        actor_type="agent",
        action=payload.operation,
        target=(
            f"{payload.target_kind}:" + ",".join(labels)
            if labels else payload.target_kind
        ),
        target_type=f"agent_{payload.surface}",
        context={
            "tenant_id": tenant_id,
            "channel": "coding_agent",
            "surface": payload.surface,
            "tool": payload.tool,
            "target_digest": payload.target_digest,
            "content_digest": payload.content_digest,
            "content_length": payload.content_length,
            "local_decision": payload.local_decision,
            "local_policy_ids": policy_ids,
            "local_findings_count": payload.local_findings_count,
            "risk_score": payload.risk_score,
            "risk_level": payload.risk_level,
            "is_sensitive": payload.is_sensitive,
            "agt_injection_risk": payload.prompt_injection_risk,
            "auth_token": "present",
            **safe_signals,
        },
    )
    decision = await enforce(
        db,
        action_request,
        ip_address=request.client.host if request.client else None,
        evaluate_full_catalog=True,
    )
    return _decision_payload(decision)


@router.post("/prompt-audit", summary="Run AGT prompt defense audit")
async def run_prompt_audit(payload: PromptAuditPayload):
    result = audit_prompt(payload.prompt)
    return {
        "is_injection_risk": result.is_injection_risk,
        "risk_score": result.risk_score,
        "findings": result.findings,
        "vectors_flagged": result.vectors_flagged,
        "recommendation": result.recommendation,
        "agt_used": result.agt_used,
    }


@router.post("/probe", summary="Run allow/block Trust Fabric smoke probe")
async def run_trust_fabric_probe(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    allow_request = ActionRequest(
        module="trust_fabric",
        actor_id="trust-probe-user",
        actor_name="Trust Probe",
        actor_type="human",
        action="read_status",
        target="trust-fabric",
        target_type="module",
        context={"probe": True, "expected": "allow"},
    )
    allow_decision = await enforce(db, allow_request, ip_address=request.client.host if request.client else None)

    deny_policy = Policy(
        name="Trust Fabric Probe: block shell execution",
        description="Temporary smoke-test policy created by /trust-fabric/probe.",
        is_active=True,
        priority=1,
        scope=PolicyScope.GLOBAL,
        condition_json=json.dumps({"field": "action", "op": "eq", "value": "shell_exec"}),
        action=PolicyAction.DENY,
        created_by="trust-fabric-probe",
    )
    db.add(deny_policy)
    await db.commit()

    try:
        block_request = ActionRequest(
            module="trust_fabric",
            actor_id="trust-probe-agent",
            actor_name="Trust Probe Agent",
            actor_type="agent",
            action="shell_exec",
            target="production-secrets",
            target_type="credential_store",
            context={"probe": True, "expected": "block", "risk_level": "critical"},
        )
        block_decision = await enforce(db, block_request, ip_address=request.client.host if request.client else None)
    finally:
        await db.delete(deny_policy)
        await db.commit()

    return {
        "allow": _decision_payload(allow_decision),
        "block": _decision_payload(block_decision),
        "passed": allow_decision.allowed and not block_decision.allowed,
    }


@router.post("/containment-probe", summary="Run non-destructive containment smoke probe")
async def run_containment_probe(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    probe_tenant = caller_tenant(user)
    probe_id = uuid.uuid4().hex[:12]
    module = Module(
        name=f"trust-probe-module-{probe_id}",
        display_name="Trust Probe Module",
        description="Temporary module created for Trust Fabric containment probe.",
        status=ModuleStatus.ACTIVE,
    )
    identity = Identity(
        name=f"Trust Probe Identity {probe_id}",
        tenant_id=probe_tenant,
        type=IdentityType.AGENT,
        status=IdentityStatus.ACTIVE,
        description="Temporary identity created for Trust Fabric containment probe.",
    )
    connector = Connector(
        name=f"Trust Probe Connector {probe_id}",
        tenant_id=probe_tenant,
        connector_type="trust_probe",
        description="Temporary connector created for Trust Fabric containment probe.",
        status=ConnectorStatus.APPROVED,
        risk_level=ConnectorRisk.LOW,
        category="Trust Fabric",
    )
    db.add_all([module, identity, connector])
    await db.commit()
    await db.refresh(module)
    await db.refresh(identity)
    await db.refresh(connector)

    try:
        module_ok = await isolate_module(
            db,
            module.name,
            "Trust Fabric containment probe",
            "trust-fabric-probe",
            tenant_id=probe_tenant,
        )
        identity_ok = await suspend_identity(
            db,
            identity.id,
            "Trust Fabric containment probe",
            "trust-fabric-probe",
            tenant_id=probe_tenant,
        )
        connector_ok = await block_connector(
            db,
            connector.id,
            "Trust Fabric containment probe",
            "trust-fabric-probe",
            tenant_id=probe_tenant,
        )

        await db.refresh(module)
        await db.refresh(identity)
        await db.refresh(connector)

        results = {
            "isolate_module": {
                "executed": module_ok,
                "target": module.name,
                "status": module.status.value,
                "passed": module_ok and module.status == ModuleStatus.QUARANTINED,
            },
            "suspend_identity": {
                "executed": identity_ok,
                "target": str(identity.id),
                "status": identity.status.value,
                "passed": identity_ok and identity.status == IdentityStatus.SUSPENDED,
            },
            "block_connector": {
                "executed": connector_ok,
                "target": str(connector.id),
                "status": connector.status.value,
                "passed": connector_ok and connector.status == ConnectorStatus.BLOCKED,
            },
        }
    finally:
        await db.delete(connector)
        await db.delete(module)
        await db.delete(identity)
        await db.commit()

    return {
        "passed": all(result["passed"] for result in results.values()),
        "results": results,
        "cleanup": "temporary probe records removed",
    }
