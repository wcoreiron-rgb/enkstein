"""
Enkstein — Autonomous Remediation Engine
Main orchestration layer: dispatch actions, handle approval gates, write audit trail.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.remediation import RemediationAction, RemediationStatus
from app.models.event import Event, EventSeverity, EventOutcome

logger = logging.getLogger("remediation_engine")

# ─── Risk level mapping ────────────────────────────────────────────────────────

# Actions that require human approval before execution
_HIGH_RISK_ACTIONS = {
    "suspend_user",
    "disable_iam_user",
    "attach_deny_policy",
    "quarantine_device",
    "revoke_token",
    "suspend_org_member",
    "remove_group_member",
    "kill_process",
}

_MEDIUM_RISK_ACTIONS = {
    "deactivate_access_key",
    "revoke_sessions",
    "force_mfa_reset",
    "delete_secret",
    "unquarantine_device",
    "unsuspend_user",
}

_LOW_RISK_ACTIONS = {
    "create_jira_ticket",
    "create_pagerduty_incident",
    "send_slack_alert",
    "call_webhook",
}

_APPROVAL_EXPIRY_MINUTES = 30


def _determine_risk(action_type: str) -> tuple[str, bool]:
    """Returns (risk_level, requires_approval)."""
    if action_type in _HIGH_RISK_ACTIONS:
        return "high", True
    if action_type in _MEDIUM_RISK_ACTIONS:
        return "medium", True
    if action_type in _LOW_RISK_ACTIONS:
        return "low", False
    return "high", True  # Unknown actions require approval by default


# ─── Provider → action module mapping ─────────────────────────────────────────

def _get_action_module(provider: str):
    """Return the action module for a given provider."""
    from app.services.remediation.actions import identity, cloud, endpoint, code, ticketing

    mapping = {
        "okta":         identity,
        "entra":        identity,
        "azure_ad":     identity,
        "aws_iam":      cloud,
        "aws":          cloud,
        "crowdstrike":  endpoint,
        "defender":     endpoint,
        "sentinelone":  endpoint,
        "s1":           endpoint,
        "github":       code,
        "jira":         ticketing,
        "pagerduty":    ticketing,
        "slack":        ticketing,
        "webhook":      ticketing,
        "generic":      ticketing,
    }
    return mapping.get(provider.lower())


async def _get_credentials(provider: str, db: AsyncSession, tenant_id: str | None = None) -> dict:
    """Retrieve credentials for the given provider via secrets manager.

    Only connectors owned by ``tenant_id`` are considered, so remediation can
    never execute against another tenant's provider credentials.
    """
    tenant_id = str(tenant_id or "").strip()
    if not tenant_id:
        logger.error("Credential lookup for provider %s refused: no tenant context", provider)
        return {}
    try:
        from app.services import secrets_manager
        from app.models.connector import Connector

        # Map provider name → connector_type used in the connectors table
        _provider_to_connector_type = {
            "okta":        "okta",
            "entra":       "microsoft",
            "azure_ad":    "microsoft",
            "aws_iam":     "aws",
            "aws":         "aws",
            "crowdstrike": "crowdstrike",
            "defender":    "defender",
            "sentinelone": "sentinelone",
            "s1":          "sentinelone",
            "github":      "github",
            "jira":        "jira",
            "pagerduty":   "pagerduty",
            "slack":       "slack",
        }
        connector_type = _provider_to_connector_type.get(provider.lower(), provider.lower())
        result = await db.execute(
            select(Connector).where(
                Connector.connector_type == connector_type,
                Connector.tenant_id == tenant_id,
            )
        )
        connectors = result.scalars().all()
        for connector in connectors:
            creds = secrets_manager.get_credential(str(connector.id), tenant_id=tenant_id)
            if creds:
                return creds if isinstance(creds, dict) else {}
    except Exception as exc:
        logger.warning(
            "Could not fetch credentials for provider %s: %s", provider, type(exc).__name__
        )
    return {}


async def _write_audit_event(
    db: AsyncSession,
    action: RemediationAction,
    event_action: str,
    outcome: EventOutcome,
    description: str,
) -> None:
    """Write an audit Event record for a remediation action."""
    try:
        event = Event(
            timestamp=datetime.utcnow(),
            source_module="remediation_engine",
            actor_id=action.triggered_by,
            actor_name=action.triggered_by,
            actor_type="automation",
            action=event_action,
            target=action.target_label or action.target_id,
            target_type=action.target_type,
            outcome=outcome,
            severity=EventSeverity.HIGH if action.risk_level in ("high", "critical") else EventSeverity.MEDIUM,
            risk_score=90.0 if action.risk_level == "critical" else 70.0 if action.risk_level == "high" else 40.0,
            description=description,
            requires_review=action.risk_level in ("high", "critical"),
            metadata_json=json.dumps({
                "remediation_action_id": str(action.id),
                "provider":    action.provider,
                "action_type": action.action_type,
                "target_id":   action.target_id,
                "risk_level":  action.risk_level,
                "playbook_id": action.playbook_id,
                "finding_id":  str(action.finding_id) if action.finding_id else None,
            }),
        )
        db.add(event)
    except Exception as exc:
        logger.warning("Failed to write audit event for remediation action %s: %s", action.id, exc)


# ─── Core execution ───────────────────────────────────────────────────────────

async def _execute_action(action: RemediationAction, db: AsyncSession) -> RemediationAction:
    """Actually run the action module. Updates action status in place."""
    action.status     = RemediationStatus.EXECUTING
    action.executed_at = datetime.now(timezone.utc)
    await db.commit()

    module = _get_action_module(action.provider)
    if module is None:
        action.status = RemediationStatus.FAILED
        action.error  = f"No action module found for provider '{action.provider}'"
        action.completed_at = datetime.now(timezone.utc)
        await _write_audit_event(db, action, "remediation_failed", EventOutcome.BLOCKED,
                                 f"No module for provider '{action.provider}'")
        await db.commit()
        return action

    try:
        credentials = await _get_credentials(action.provider, db, action.tenant_id)
        params      = json.loads(action.parameters) if action.parameters else {}
        result      = await module.execute(
            action_type=action.action_type,
            target_id=action.target_id,
            params=params,
            credentials=credentials,
        )
        action.completed_at = datetime.now(timezone.utc)
        if result.success:
            action.status        = RemediationStatus.COMPLETED
            action.rollback_data = json.dumps(result.rollback_data)
            action.output        = json.dumps(result.output)
            await _write_audit_event(
                db, action, "remediation_completed", EventOutcome.ALLOWED,
                f"Remediation '{action.action_type}' on {action.target_label or action.target_id} completed: {result.message}",
            )
        else:
            action.status = RemediationStatus.FAILED
            action.error  = result.error or result.message
            await _write_audit_event(
                db, action, "remediation_failed", EventOutcome.BLOCKED,
                f"Remediation '{action.action_type}' failed: {result.message}",
            )
    except Exception as exc:
        action.status       = RemediationStatus.FAILED
        action.error        = str(exc)
        action.completed_at = datetime.now(timezone.utc)
        logger.exception("Unexpected error executing remediation action %s", action.id)
        await _write_audit_event(
            db, action, "remediation_error", EventOutcome.BLOCKED,
            f"Remediation '{action.action_type}' errored: {exc}",
        )

    await db.commit()
    return action


# ─── Public API ───────────────────────────────────────────────────────────────

async def execute_remediation(
    action_spec: dict,
    db: AsyncSession,
    finding_id: UUID | None = None,
    workflow_run_id: UUID | None = None,
    playbook_id: str | None = None,
    triggered_by: str = "auto",
    tenant_id: str | None = None,
) -> RemediationAction:
    """
    Create and (if auto-approved) execute a remediation action.

    action_spec keys: provider, action_type, target_id, target_type, target_label, parameters

    ``tenant_id`` is required: an unowned action would later resolve
    credentials and targets with no tenant boundary.
    """
    tenant_id = str(tenant_id or "").strip()
    if not tenant_id:
        raise ValueError("Remediation requires tenant context")

    provider    = action_spec.get("provider", "generic")
    action_type = action_spec.get("action_type", "send_slack_alert")
    target_id   = str(action_spec.get("target_id", "unknown"))
    target_type = action_spec.get("target_type", "unknown")
    target_label = action_spec.get("target_label", target_id)
    parameters  = action_spec.get("parameters", {})

    risk_level, requires_approval = _determine_risk(action_type)

    now = datetime.now(timezone.utc)

    action = RemediationAction(
        finding_id       = finding_id,
        tenant_id        = tenant_id,
        workflow_run_id  = workflow_run_id,
        playbook_id      = playbook_id,
        provider         = provider,
        action_type      = action_type,
        target_type      = target_type,
        target_id        = target_id,
        target_label     = target_label,
        parameters       = json.dumps(parameters) if isinstance(parameters, dict) else parameters,
        risk_level       = risk_level,
        requires_approval= requires_approval,
        triggered_by     = triggered_by,
        status           = RemediationStatus.PENDING_APPROVAL if requires_approval else RemediationStatus.APPROVED,
        approval_expires_at = now + timedelta(minutes=_APPROVAL_EXPIRY_MINUTES) if requires_approval else None,
        created_at       = now,
        updated_at       = now,
    )
    db.add(action)
    await db.flush()  # Get ID

    await _write_audit_event(
        db, action,
        "remediation_queued" if requires_approval else "remediation_auto_approved",
        EventOutcome.PENDING if requires_approval else EventOutcome.ALLOWED,
        f"Remediation '{action_type}' on {target_label} "
        + ("queued for approval" if requires_approval else "auto-approved (low risk)"),
    )
    await db.commit()

    # Auto-execute low-risk actions immediately
    if not requires_approval:
        action = await _execute_action(action, db)

    return action


async def approve_remediation(
    action_id: UUID,
    approved_by: str,
    db: AsyncSession,
) -> RemediationAction:
    """Approve a pending remediation action and execute it."""
    result = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = result.scalar_one_or_none()

    if action is None:
        raise ValueError(f"Remediation action {action_id} not found")

    if action.status != RemediationStatus.PENDING_APPROVAL:
        raise ValueError(f"Action {action_id} is not pending approval (current status: {action.status})")

    # Check expiry
    now = datetime.now(timezone.utc)
    if action.approval_expires_at and now > action.approval_expires_at.replace(tzinfo=timezone.utc if action.approval_expires_at.tzinfo is None else action.approval_expires_at.tzinfo):
        action.status     = RemediationStatus.TIMED_OUT
        action.updated_at = now
        await db.commit()
        raise ValueError(f"Approval window expired at {action.approval_expires_at}")

    action.status      = RemediationStatus.APPROVED
    action.approved_by = approved_by
    action.updated_at  = now

    await _write_audit_event(
        db, action, "remediation_approved", EventOutcome.ALLOWED,
        f"Remediation '{action.action_type}' approved by {approved_by}",
    )
    await db.commit()

    return await _execute_action(action, db)


async def reject_remediation(
    action_id: UUID,
    rejected_by: str,
    reason: str,
    db: AsyncSession,
) -> RemediationAction:
    """Reject a pending remediation action."""
    result = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = result.scalar_one_or_none()

    if action is None:
        raise ValueError(f"Remediation action {action_id} not found")

    if action.status != RemediationStatus.PENDING_APPROVAL:
        raise ValueError(f"Action {action_id} is not pending approval (current status: {action.status})")

    now = datetime.now(timezone.utc)
    action.status          = RemediationStatus.REJECTED
    action.approved_by     = rejected_by
    action.rejected_reason = reason
    action.updated_at      = now
    action.completed_at    = now

    await _write_audit_event(
        db, action, "remediation_rejected", EventOutcome.BLOCKED,
        f"Remediation '{action.action_type}' rejected by {rejected_by}: {reason}",
    )
    await db.commit()
    return action


async def rollback_remediation(
    action_id: UUID,
    db: AsyncSession,
) -> RemediationAction:
    """Roll back a completed remediation action using stored rollback_data."""
    result = await db.execute(select(RemediationAction).where(RemediationAction.id == action_id))
    action = result.scalar_one_or_none()

    if action is None:
        raise ValueError(f"Remediation action {action_id} not found")

    if action.status != RemediationStatus.COMPLETED:
        raise ValueError(f"Can only roll back COMPLETED actions (current status: {action.status})")

    rollback_data = json.loads(action.rollback_data) if action.rollback_data else {}
    module        = _get_action_module(action.provider)

    if module is None:
        raise ValueError(f"No action module for provider '{action.provider}'")

    try:
        credentials = await _get_credentials(action.provider, db, action.tenant_id)
        result_rb   = await module.rollback(
            action_type  = action.action_type,
            target_id    = action.target_id,
            rollback_data = rollback_data,
            credentials  = credentials,
        )
        now = datetime.now(timezone.utc)
        if result_rb.success:
            action.status     = RemediationStatus.ROLLED_BACK
            action.updated_at = now
            await _write_audit_event(
                db, action, "remediation_rolled_back", EventOutcome.ALLOWED,
                f"Remediation '{action.action_type}' rolled back: {result_rb.message}",
            )
        else:
            action.error      = result_rb.error or result_rb.message
            action.updated_at = now
            await _write_audit_event(
                db, action, "remediation_rollback_failed", EventOutcome.BLOCKED,
                f"Rollback of '{action.action_type}' failed: {result_rb.message}",
            )
        await db.commit()
    except Exception as exc:
        logger.exception("Rollback error for action %s", action_id)
        action.error      = str(exc)
        action.updated_at = datetime.now(timezone.utc)
        await db.commit()

    return action
