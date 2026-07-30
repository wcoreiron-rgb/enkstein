"""
Enkstein — Remediation Playbooks
Built-in playbook definitions + auto-trigger logic.

Call check_and_trigger(finding, db) from finding_pipeline after ingesting
critical/high findings to automatically match and execute playbooks.
"""
from __future__ import annotations

import json
import logging
from typing import Any, TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.remediation import RemediationAction, RemediationPlaybook

if TYPE_CHECKING:
    from app.models.finding import Finding

logger = logging.getLogger("remediation_playbooks")

# ─── Built-in playbook definitions ────────────────────────────────────────────

BUILTIN_PLAYBOOKS: list[dict] = [
    {
        "slug":             "compromised-credential",
        "name":             "Compromised Credential Response",
        "description":      "Suspend user + revoke sessions + page on-call when credential compromise detected",
        "trigger_severity": "critical",
        "trigger_keywords": ["credential", "compromised", "stolen", "leaked", "exposed password", "password leak"],
        "requires_approval": True,
        "actions": [
            {
                "provider":       "okta",
                "action_type":    "suspend_user",
                "target_from":    "finding.actor_id",
                "target_type":    "user",
                "risk_level":     "high",
            },
            {
                "provider":       "okta",
                "action_type":    "revoke_sessions",
                "target_from":    "finding.actor_id",
                "target_type":    "user",
                "risk_level":     "medium",
            },
            {
                "provider":       "pagerduty",
                "action_type":    "create_pagerduty_incident",
                "target_type":    "alert",
                "risk_level":     "low",
                "params": {
                    "urgency": "high",
                    "title":   "Compromised credential detected — {finding.title}",
                },
            },
            {
                "provider":       "jira",
                "action_type":    "create_jira_ticket",
                "target_type":    "ticket",
                "risk_level":     "low",
                "params": {
                    "priority": "Critical",
                    "summary":  "Compromised Credential: {finding.title}",
                },
            },
        ],
    },
    {
        "slug":             "exposed-secret",
        "name":             "Exposed Secret Response",
        "description":      "Revoke token/key + notify owner when secret is detected in code",
        "trigger_claw":     "devclaw",
        "trigger_severity": "critical",
        "trigger_keywords": ["secret", "api key", "token", "private key", "password", "credential exposed"],
        "requires_approval": True,
        "actions": [
            {
                "provider":       "github",
                "action_type":    "revoke_token",
                "target_from":    "finding.resource_id",
                "target_type":    "token",
                "risk_level":     "medium",
            },
            {
                "provider":       "aws_iam",
                "action_type":    "deactivate_access_key",
                "target_from":    "finding.resource_id",
                "target_type":    "access_key",
                "risk_level":     "medium",
            },
            {
                "provider":       "slack",
                "action_type":    "send_slack_alert",
                "target_type":    "channel",
                "risk_level":     "low",
                "params": {
                    "text": ":rotating_light: Secret exposed in code: {finding.title}",
                },
            },
            {
                "provider":       "jira",
                "action_type":    "create_jira_ticket",
                "target_type":    "ticket",
                "risk_level":     "low",
                "params": {
                    "priority": "Critical",
                    "summary":  "Exposed Secret: {finding.title}",
                },
            },
        ],
    },
    {
        "slug":             "endpoint-compromise",
        "name":             "Endpoint Compromise Response",
        "description":      "Quarantine device + notify SOC when endpoint compromise detected",
        "trigger_claw":     "endpointclaw",
        "trigger_severity": "critical",
        "trigger_keywords": [],
        "requires_approval": True,
        "actions": [
            {
                "provider":       "crowdstrike",
                "action_type":    "quarantine_device",
                "target_from":    "finding.resource_id",
                "target_type":    "device",
                "risk_level":     "high",
            },
            {
                "provider":       "pagerduty",
                "action_type":    "create_pagerduty_incident",
                "target_type":    "alert",
                "risk_level":     "low",
                "params": {
                    "urgency": "high",
                    "title":   "Endpoint Compromise Detected — {finding.title}",
                },
            },
            {
                "provider":       "slack",
                "action_type":    "send_slack_alert",
                "target_type":    "channel",
                "risk_level":     "low",
                "params": {
                    "text": ":rotating_light: Endpoint compromised: {finding.title} on {finding.resource_name}",
                },
            },
        ],
    },
    {
        "slug":             "privilege-escalation",
        "name":             "Privilege Escalation Response",
        "description":      "Remove elevated role + suspend user when privilege escalation detected",
        "trigger_severity": "critical",
        "trigger_keywords": ["privilege escalation", "elevated", "admin access", "root", "sudo", "privilege abuse"],
        "requires_approval": True,
        "actions": [
            {
                "provider":       "okta",
                "action_type":    "suspend_user",
                "target_from":    "finding.actor_id",
                "target_type":    "user",
                "risk_level":     "high",
            },
            {
                "provider":       "aws_iam",
                "action_type":    "attach_deny_policy",
                "target_from":    "finding.actor_id",
                "target_type":    "iam_user",
                "risk_level":     "high",
            },
            {
                "provider":       "pagerduty",
                "action_type":    "create_pagerduty_incident",
                "target_type":    "alert",
                "risk_level":     "low",
                "params": {
                    "urgency": "high",
                    "title":   "Privilege Escalation Detected — {finding.title}",
                },
            },
        ],
    },
    {
        "slug":             "data-exfiltration",
        "name":             "Data Exfiltration Response",
        "description":      "Revoke sessions + notify CISO when data exfiltration detected",
        "trigger_severity": "critical",
        "trigger_keywords": ["exfiltration", "data loss", "dlp", "unauthorized transfer", "data leak", "exfil"],
        "requires_approval": True,
        "actions": [
            {
                "provider":       "okta",
                "action_type":    "revoke_sessions",
                "target_from":    "finding.actor_id",
                "target_type":    "user",
                "risk_level":     "medium",
            },
            {
                "provider":       "slack",
                "action_type":    "send_slack_alert",
                "target_type":    "channel",
                "risk_level":     "low",
                "params": {
                    "text": ":rotating_light: CRITICAL: Data exfiltration detected — {finding.title}",
                },
            },
            {
                "provider":       "pagerduty",
                "action_type":    "create_pagerduty_incident",
                "target_type":    "alert",
                "risk_level":     "low",
                "params": {
                    "urgency": "high",
                    "title":   "Data Exfiltration Detected — {finding.title}",
                },
            },
            {
                "provider":       "jira",
                "action_type":    "create_jira_ticket",
                "target_type":    "ticket",
                "risk_level":     "low",
                "params": {
                    "priority": "Critical",
                    "summary":  "Data Exfiltration Incident: {finding.title}",
                },
            },
        ],
    },
]


# ─── DB seeding ───────────────────────────────────────────────────────────────

async def seed_builtin_playbooks(db: AsyncSession) -> None:
    """Ensure all built-in playbooks exist in the DB (idempotent)."""
    for spec in BUILTIN_PLAYBOOKS:
        existing = await db.execute(
            select(RemediationPlaybook).where(RemediationPlaybook.slug == spec["slug"])
        )
        if existing.scalar_one_or_none() is not None:
            continue  # Already seeded

        playbook = RemediationPlaybook(
            slug                  = spec["slug"],
            name                  = spec["name"],
            description           = spec.get("description"),
            trigger_claw          = spec.get("trigger_claw"),
            trigger_severity      = spec.get("trigger_severity"),
            trigger_category      = spec.get("trigger_category"),
            trigger_keywords      = json.dumps(spec.get("trigger_keywords", [])),
            actions_json          = json.dumps(spec.get("actions", [])),
            is_active             = True,
            requires_approval     = spec.get("requires_approval", True),
            auto_rollback_on_failure = spec.get("auto_rollback_on_failure", False),
        )
        db.add(playbook)
    await db.commit()


# ─── Matching helpers ─────────────────────────────────────────────────────────

def _keywords_match(finding: "Finding", keywords: list[str]) -> bool:
    """Case-insensitive keyword match against finding title + description."""
    if not keywords:
        return True  # No keywords specified = match all
    haystack = (
        (finding.title or "").lower()
        + " "
        + (finding.description or "").lower()
    )
    return any(kw.lower() in haystack for kw in keywords)


def _severity_matches(finding: "Finding", trigger_severity: str | None) -> bool:
    """Check if finding severity meets the trigger threshold."""
    if not trigger_severity:
        return True
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    finding_rank  = severity_rank.get(str(finding.severity).lower(), 0)
    trigger_rank  = severity_rank.get(trigger_severity.lower(), 0)
    return finding_rank >= trigger_rank


def _resolve_target(target_from: str | None, finding: "Finding", default: str = "unknown") -> str:
    """Resolve target_id from a dot-path like 'finding.resource_id'."""
    if not target_from:
        return default
    if target_from.startswith("finding."):
        attr = target_from[len("finding."):]
        return str(getattr(finding, attr, None) or default)
    return default


def _build_context(finding: "Finding") -> dict:
    """Build a template context dict from a finding."""
    return {
        "finding.title":         finding.title or "",
        "finding.description":   finding.description or "",
        "finding.severity":      str(finding.severity),
        "finding.claw":          finding.claw or "",
        "finding.provider":      finding.provider or "",
        "finding.resource_id":   finding.resource_id or "",
        "finding.resource_name": finding.resource_name or "",
        "finding.category":      finding.category or "",
        "finding.actor_id":      finding.resource_id or "",  # Best-effort
        "title":                 finding.title or "",
        "severity":              str(finding.severity),
    }


# ─── Main auto-trigger ────────────────────────────────────────────────────────

async def check_and_trigger(
    finding: "Finding",
    db: AsyncSession,
) -> list[RemediationAction]:
    """
    Called by finding_pipeline after ingesting a critical/high finding.
    Matches active playbooks and triggers their actions via the engine.
    Returns the list of RemediationAction records created.
    """
    # Ensure built-ins are seeded
    try:
        await seed_builtin_playbooks(db)
    except Exception as exc:
        logger.warning("Playbook seeding failed (non-fatal): %s", exc)

    # Load all active playbooks
    result = await db.execute(
        select(RemediationPlaybook).where(RemediationPlaybook.is_active == True)  # noqa: E712
    )
    playbooks = result.scalars().all()

    from app.services.remediation.engine import execute_remediation

    triggered_actions: list[RemediationAction] = []
    context = _build_context(finding)

    for playbook in playbooks:
        # Check trigger conditions
        trigger_claw     = playbook.trigger_claw
        trigger_severity = playbook.trigger_severity
        keywords_raw     = playbook.trigger_keywords
        keywords         = json.loads(keywords_raw) if keywords_raw else []

        claw_match     = (not trigger_claw) or (finding.claw == trigger_claw)
        severity_match = _severity_matches(finding, trigger_severity)
        keyword_match  = _keywords_match(finding, keywords)

        if not (claw_match and severity_match and keyword_match):
            continue

        logger.info(
            "Playbook '%s' matched finding '%s' (severity=%s, claw=%s)",
            playbook.name, finding.title[:80], finding.severity, finding.claw,
        )

        # Execute each action in the playbook
        actions_spec = json.loads(playbook.actions_json) if playbook.actions_json else []
        for action_spec in actions_spec:
            try:
                target_from  = action_spec.get("target_from")
                target_id    = _resolve_target(target_from, finding, finding.resource_id or "unknown")
                params       = dict(action_spec.get("params", {}))

                # Inject context into params for template substitution
                params["_context"] = context
                for k, v in context.items():
                    for pk in list(params.keys()):
                        if isinstance(params[pk], str):
                            params[pk] = params[pk].replace(f"{{{k}}}", v)

                action = await execute_remediation(
                    action_spec={
                        "provider":      action_spec.get("provider", "generic"),
                        "action_type":   action_spec.get("action_type", "send_slack_alert"),
                        "target_id":     target_id,
                        "target_type":   action_spec.get("target_type", "unknown"),
                        "target_label":  target_id,
                        "parameters":    params,
                    },
                    db=db,
                    finding_id=finding.id,
                    playbook_id=str(playbook.id),
                    triggered_by="playbook",
                    tenant_id=finding.tenant_id,
                )
                triggered_actions.append(action)
            except Exception as exc:
                logger.warning(
                    "Failed to trigger playbook action %s for finding %s: %s",
                    action_spec.get("action_type"), finding.id, exc,
                )

        # Increment run counter
        try:
            playbook.run_count = (playbook.run_count or 0) + 1
            await db.commit()
        except Exception:
            pass

    return triggered_actions
