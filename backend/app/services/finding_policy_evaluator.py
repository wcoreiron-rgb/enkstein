"""
Enkstein — Finding Policy Evaluator
Evaluates security findings against the policy engine and emits Event records
for every policy violation or DENY/REQUIRE_APPROVAL decision.

Called automatically by finding_pipeline.py for HIGH and CRITICAL findings.
Can also be called directly for manual re-evaluation.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity
from app.models.event import Event, EventSeverity, EventOutcome
from app.models.policy import PolicyAction
from app.services.policy_engine import evaluate_action

logger = logging.getLogger("finding_policy_evaluator")


def _finding_to_context(finding: Finding) -> dict[str, Any]:
    """
    Convert a Finding ORM object into a policy evaluation context dict.
    Context keys map 1:1 to policy condition_json 'field' values.

    Example policies that can match:
      {"field": "severity", "op": "eq", "value": "critical"}
      {"field": "claw", "op": "eq", "value": "cloudclaw"}
      {"field": "risk_score", "op": "gte", "value": 80}
      {"field": "actively_exploited", "op": "eq", "value": true}
      {"field": "category", "op": "eq", "value": "vulnerability"}
      {"field": "provider", "op": "in", "value": ["nvd", "cisa_kev"]}
    """
    return {
        # Core identifiers
        "claw": finding.claw,
        "provider": finding.provider,
        "category": finding.category or "",

        # Severity / scoring
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "cvss_score": finding.cvss_score or 0.0,
        "epss_score": finding.epss_score or 0.0,
        "actively_exploited": finding.actively_exploited,

        # Status
        "status": finding.status,

        # Resource context (for cloud / endpoint claws)
        "resource_type": finding.resource_type or "",
        "resource_id": finding.resource_id or "",
        "region": finding.region or "",
        "account_id": finding.account_id or "",

        # Text fields (for contains / startswith policies)
        "title": finding.title,
        "external_id": finding.external_id or "",
    }


def _outcome_from_policy_action(action: PolicyAction) -> EventOutcome:
    mapping = {
        PolicyAction.ALLOW:            EventOutcome.ALLOWED,
        PolicyAction.MONITOR:          EventOutcome.ALLOWED,
        PolicyAction.DENY:             EventOutcome.BLOCKED,
        PolicyAction.REQUIRE_APPROVAL: EventOutcome.REQUIRES_APPROVAL,
        PolicyAction.ISOLATE:          EventOutcome.BLOCKED,
    }
    return mapping.get(action, EventOutcome.FLAGGED)


async def evaluate_findings(
    db: AsyncSession,
    findings: list[Finding],
) -> int:
    """
    Evaluate a list of findings against active policies.
    Creates Event records for any non-ALLOW policy matches.

    Returns the number of policy violations found.
    """
    violations = 0

    for finding in findings:
        try:
            context = _finding_to_context(finding)
            result = await evaluate_action(db, context, module=finding.claw)

            # Only emit an event when a real policy matched (not default allow)
            if result.policy_name == "default":
                continue

            outcome = _outcome_from_policy_action(result.action)
            is_violation = result.action in (PolicyAction.DENY, PolicyAction.ISOLATE, PolicyAction.REQUIRE_APPROVAL)

            if is_violation:
                violations += 1

            # Map finding severity to event severity
            sev_map = {
                FindingSeverity.CRITICAL: EventSeverity.CRITICAL,
                FindingSeverity.HIGH:     EventSeverity.HIGH,
                FindingSeverity.MEDIUM:   EventSeverity.MEDIUM,
                FindingSeverity.LOW:      EventSeverity.LOW,
                FindingSeverity.INFO:     EventSeverity.INFO,
            }

            event = Event(
                timestamp=datetime.utcnow(),
                source_module=finding.claw,
                actor_id=finding.provider,
                actor_name=finding.provider,
                actor_type="data_source",
                action="policy_evaluated",
                target=finding.title[:512],
                target_type="finding",
                outcome=outcome,
                severity=sev_map.get(finding.severity, EventSeverity.INFO),
                risk_score=finding.risk_score,
                policy_id=str(result.policy_name),   # using name as ID for lookup
                policy_name=result.policy_name,
                policy_reason=result.reason,
                description=(
                    f"Policy '{result.policy_name}' evaluated for {finding.severity} finding: "
                    f"{finding.title[:200]}. Action: {result.action}"
                ),
                metadata_json=json.dumps({
                    "finding_id": str(finding.id),
                    "claw": finding.claw,
                    "policy_action": result.action,
                    "policy_name": result.policy_name,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "actively_exploited": finding.actively_exploited,
                    "context_snapshot": context,
                }),
                is_anomaly=finding.actively_exploited,
                requires_review=is_violation,
            )
            db.add(event)

        except Exception as exc:
            logger.error(
                "Error evaluating policy for finding %s [%s]: %s",
                finding.id, finding.claw, exc, exc_info=True,
            )

    if violations > 0:
        await db.commit()

    return violations


async def evaluate_single_finding(
    db: AsyncSession,
    finding_id: str,
) -> dict:
    """
    Re-evaluate a single finding by ID. Useful for manual re-checks or API endpoints.
    Returns the policy evaluation result.
    """
    from sqlalchemy import select
    from app.models.finding import Finding as FindingModel
    import uuid

    result = await db.execute(
        select(FindingModel).where(FindingModel.id == uuid.UUID(finding_id))
    )
    finding = result.scalar_one_or_none()
    if not finding:
        return {"error": f"Finding {finding_id} not found"}

    context = _finding_to_context(finding)
    policy_result = await evaluate_action(db, context, module=finding.claw)

    return {
        "finding_id": finding_id,
        "policy_name": policy_result.policy_name,
        "action": policy_result.action,
        "reason": policy_result.reason,
        "allowed": policy_result.allowed,
    }
