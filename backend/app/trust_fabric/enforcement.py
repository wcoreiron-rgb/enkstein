"""
Trust Fabric — Enforcement Layer
The core zero-trust action mediation for Enkstein.
Every action is verified before execution. No anonymous execution.
"""
import json
from datetime import datetime
from typing import Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.policy_engine import evaluate_action, PolicyResult
from app.services.risk_scoring import calculate_event_risk, severity_from_score
from app.services.audit_service import log_action
from app.services.ring_policy import (
    ACTION_RING_MAP,
    CHANNEL_RING_MAP,
    classify_ring,
    evaluate_ring,
)
from app.models.event import Event, EventOutcome, EventSeverity
from app.models.policy import PolicyAction
from app.trust_fabric.anomaly import detect_anomalies


class ActionRequest:
    """Represents a request for an action by a module/agent."""

    def __init__(
        self,
        module: str,
        actor_id: str,
        actor_name: str,
        actor_type: str,
        action: str,
        target: Optional[str] = None,
        target_type: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ):
        self.module = module
        self.actor_id = actor_id
        self.actor_name = actor_name
        self.actor_type = actor_type
        self.action = action
        self.target = target
        self.target_type = target_type
        self.context = context or {}
        self.timestamp = datetime.utcnow()


class EnforcementDecision:
    """The Trust Fabric decision for an ActionRequest."""

    def __init__(
        self,
        allowed: bool,
        outcome: EventOutcome,
        risk_score: float,
        severity: EventSeverity,
        policy_name: str,
        reason: str,
        anomalies: list[str],
    ):
        self.allowed = allowed
        self.outcome = outcome
        self.risk_score = risk_score
        self.severity = severity
        self.policy_name = policy_name
        self.reason = reason
        self.anomalies = anomalies


async def enforce(
    db: AsyncSession,
    request: ActionRequest,
    ip_address: Optional[str] = None,
) -> EnforcementDecision:
    """
    Main enforcement entrypoint.
    1. Detect anomalies
    2. Evaluate policy
    3. Calculate risk
    4. Log event + audit
    5. Return decision
    """
    # Build full evaluation context
    eval_context = {
        "module": request.module,
        "actor_id": request.actor_id,
        "actor_type": request.actor_type,
        "action": request.action,
        "target": request.target,
        "target_type": request.target_type,
        **request.context,
    }

    # 1. Anomaly detection
    anomalies = await detect_anomalies(db, request)

    # 2. Ring-policy evaluation (before standard policy engine)
    # Apply only when action/channel are ring-classified or explicitly requested.
    channel = str(request.context.get("channel", "") or "")
    ring_enforce = bool(
        request.context.get("enforce_ring_policy")
        or request.action in ACTION_RING_MAP
        or channel in CHANNEL_RING_MAP
    )
    ring_meta: dict[str, Any] | None = None
    if ring_enforce:
        ring = classify_ring(request.action, channel)
        trust_score = float(request.context.get("trust_score", 50.0))
        caller_role = str(request.context.get("caller_role", "viewer"))
        ring_result = evaluate_ring(ring, trust_score=trust_score, caller_role=caller_role)
        ring_meta = {
            "enabled": True,
            "ring": ring,
            "trust_score": trust_score,
            "caller_role": caller_role,
            "allowed": ring_result["allowed"],
            "requires_approval": ring_result["requires_approval"],
            "approvals_required": ring_result["approvals_required"],
            "policy_name": ring_result["policy_name"],
        }
        if not ring_result["allowed"] and not ring_result["requires_approval"]:
            policy_result = PolicyResult(
                action=PolicyAction.DENY,
                policy_name=ring_result["policy_name"],
                reason=ring_result["deny_reason"] or f"Denied by ring policy ({ring})",
            )
        elif ring_result["requires_approval"]:
            policy_result = PolicyResult(
                action=PolicyAction.REQUIRE_APPROVAL,
                policy_name="execution_ring_policy",
                reason=f"Ring policy requires approval ({ring}, approvals_required={ring_result['approvals_required']})",
            )
        else:
            policy_result = PolicyResult(
                action=PolicyAction.ALLOW,
                policy_name="execution_ring_policy",
                reason=f"Allowed by ring policy ({ring})",
            )
    else:
        # 3. Standard policy evaluation
        policy_result = await evaluate_action(db, eval_context, module=request.module)

    # 4. Risk scoring
    signals = list(anomalies)
    if not policy_result.allowed:
        signals.append("blocked_policy")
    if request.actor_type == "agent":
        signals.append("identity_anomaly") if anomalies else None

    risk_score = calculate_event_risk(signals)
    sev_str = severity_from_score(risk_score)
    severity = EventSeverity(sev_str)

    # 5. Map outcome
    outcome_map = {
        PolicyAction.ALLOW: EventOutcome.ALLOWED,
        PolicyAction.DENY: EventOutcome.BLOCKED,
        PolicyAction.REQUIRE_APPROVAL: EventOutcome.REQUIRES_APPROVAL,
        PolicyAction.MONITOR: EventOutcome.ALLOWED,
        PolicyAction.ISOLATE: EventOutcome.BLOCKED,
    }
    outcome = outcome_map.get(policy_result.action, EventOutcome.FLAGGED)

    # 6. Persist event
    event = Event(
        timestamp=request.timestamp,
        source_module=request.module,
        actor_id=request.actor_id,
        actor_name=request.actor_name,
        actor_type=request.actor_type,
        action=request.action,
        target=request.target,
        target_type=request.target_type,
        outcome=outcome,
        severity=severity,
        risk_score=risk_score,
        policy_name=policy_result.policy_name,
        policy_reason=policy_result.reason,
        description=f"[{request.module}] {request.actor_name} → {request.action}",
        metadata_json=json.dumps({"anomalies": anomalies, "context": request.context, "ring": ring_meta}),
        is_anomaly=bool(anomalies),
        requires_review=risk_score >= 50 or outcome == EventOutcome.REQUIRES_APPROVAL,
    )
    db.add(event)

    # 7. Audit log
    await log_action(
        db=db,
        actor=request.actor_name,
        actor_type=request.actor_type,
        action=request.action,
        outcome=outcome.value,
        resource_type=request.target_type,
        resource_id=request.target,
        policy_applied=policy_result.policy_name,
        reason=policy_result.reason,
        module=request.module,
        ip_address=ip_address,
        detail_json=json.dumps({"risk_score": risk_score, "anomalies": anomalies, "ring": ring_meta}),
        compliance_relevant=risk_score >= 25,
    )

    await db.commit()

    return EnforcementDecision(
        allowed=policy_result.allowed,
        outcome=outcome,
        risk_score=risk_score,
        severity=severity,
        policy_name=policy_result.policy_name,
        reason=policy_result.reason,
        anomalies=anomalies,
    )
